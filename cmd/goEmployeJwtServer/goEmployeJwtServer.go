package main

import (
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/config"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/database"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/goHttpEcho"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/golog"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/metadata"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/tools"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-employe-jwt/pkg/f5"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-employe-jwt/pkg/version"
	"log"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
)

const (
	defaultPort                  = 8080
	defaultDBPort                = 5432
	defaultDBIp                  = "127.0.0.1"
	defaultDBSslMode             = "prefer"
	defaultRestrictedUrlBasePath = "/goapi/v1"
	defaultJwtCookieName         = "goJWT_token"
	defaultWebRootDir            = "goEmployeJwtFront/dist/"
	defaultAdminUser             = "goadmin"
	defaultAdminEmail            = "goadmin@yourdomain.org"
	defaultAdminId               = 960901
	/*
		charsetUTF8                  = "charset=UTF-8"
		MIMEHtml                     = "text/html"
		MIMEHtmlCharsetUTF8          = MIMEHtml + "; " + charsetUTF8

	*/
)

// content holds our static web server content.
//
//go:embed goEmployeJwtFront/dist/*
var content embed.FS

// UserLogin defines model for UserLogin.
type UserLogin struct {
	PasswordHash string `json:"password_hash"`
	Username     string `json:"username"`
}
type Service struct {
	// AllowedHostnames is a list of strings which will be matched to the client
	// requesting for a connection upgrade to a websocket connection
	AllowedHostnames []string
	Logger           golog.MyLogger
	Store            f5.Storage
	dbConn           database.DB
	server           *goHttpEcho.Server
	auth             f5.Authentication
	jwtCookieName    string
}

// GetJwtCookieNameFromEnv returns a the name of the http-only cookie to be used to use JWT from env variable
// JWT_COOKIE_NAME : should exist and contain a string with your cookie name or this function will use the passed default
func GetJwtCookieNameFromEnv(defaultName string) string {
	val, exist := os.LookupEnv("JWT_COOKIE_NAME")
	if !exist {
		return defaultName
	}
	return fmt.Sprintf("%s", val)
}

func cookieToHeaderMiddleware(cookieName string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// If the Authorization header is already present, do nothing.
			if c.Request().Header.Get("Authorization") != "" {
				return next(c)
			}

			cookie, err := c.Cookie(cookieName) // Use the provided cookieName
			if err == nil {
				// If the cookie exists, create the Bearer token header.
				bearerToken := "Bearer " + cookie.Value
				c.Request().Header.Set("Authorization", bearerToken)
			}

			return next(c)
		}
	}
}

func validateHostAllowed(r *http.Request, allowedHostnames []string, l golog.MyLogger) error {
	requesterHostname := r.Host
	l.Info("validateHostAllowed(remote host: %s)", requesterHostname)
	if slices.Contains(allowedHostnames, "*") {
		return nil
	}
	if strings.Index(requesterHostname, ":") != -1 {
		requesterHostname = strings.Split(requesterHostname, ":")[0]
	}
	if slices.Contains(allowedHostnames, "localhost") {
		if requesterHostname == "127.0.0.1" || requesterHostname == "::1" {
			return nil
		}
	}
	for _, allowedHostname := range allowedHostnames {
		if requesterHostname == allowedHostname {
			return nil
		}
	}
	msgErr := fmt.Sprintf("failed to find '%s' in the list of allowed hostnames", requesterHostname)
	l.Warn(msgErr)
	return errors.New(msgErr)
}

func (s Service) getJwtCookieFromF5(ctx echo.Context) error {
	s.Logger.TraceHttpRequest("getJwtCookieFromF5", ctx.Request())
	err := validateHostAllowed(ctx.Request(), s.AllowedHostnames, s.Logger)
	if err != nil {
		errMsg := fmt.Sprintf("error validating host: %v", err)
		s.Logger.Error(errMsg)
		return ctx.JSON(http.StatusUnauthorized, errMsg)
	}
	// get the user from the F5 Header UserId
	login := strings.TrimSpace(ctx.Request().Header.Get("UserId"))
	if login == "" {
		myErrMsg := "getJwtCookieFromF5 failed to get login because UserId F5 header is missing"
		s.Logger.Warn(myErrMsg)
		return ctx.JSON(http.StatusUnauthorized, map[string]string{"status": myErrMsg})
	} else {
		s.Logger.Debug("About to check username: %s ", login)
		err := f5.ValidateLogin(login)
		if err != nil {
			errMsg := fmt.Sprintf("error validating user login: %v", err)
			s.Logger.Error(errMsg)
			return ctx.JSON(http.StatusBadRequest, errMsg)
		}
		h := sha256.New()
		h.Write([]byte(version.APP))
		// just to get a valid hash, not used with F5
		appPasswordHash := fmt.Sprintf("%x", h.Sum(nil))
		if s.auth.AuthenticateUser(login, appPasswordHash) {
			userInfo, err := s.server.Authenticator.GetUserInfoFromLogin(login)
			if err != nil {
				myErrMsg := fmt.Sprintf("getJwtCookieFromF5 failed to get user info from login: %v", err)
				s.Logger.Error(myErrMsg)
				return ctx.JSON(http.StatusInternalServerError, map[string]string{"status": myErrMsg})
			}
			token, err := s.server.JwtCheck.GetTokenFromUserInfo(userInfo)
			if err != nil {
				myErrMsg := fmt.Sprintf("getJwtCookieFromF5 failed to get jwt token from user info: %v", err)
				s.Logger.Error(myErrMsg)
				return ctx.JSON(http.StatusInternalServerError, map[string]string{"status": myErrMsg})
			}
			// Prepare the http only cookie for jwt token
			cookie := new(http.Cookie)
			cookie.Name = s.jwtCookieName
			cookie.Path = "/"
			cookie.Value = token.String()
			cookie.Expires = time.Now().Add(24 * time.Hour) // Set expiration
			cookie.HttpOnly = true                          // ⭐ Most important part: prevents JS access
			cookie.Secure = true                            // Only send over HTTPS
			cookie.SameSite = http.SameSiteLaxMode          // CSRF protection
			ctx.SetCookie(cookie)
			myMsg := fmt.Sprintf("getJwtCookieFromF5(%s) successful, token set in HTTP-Only cookie.", login)
			s.Logger.Info(myMsg)
			return ctx.JSON(http.StatusOK, myMsg)
		} else {
			myErrMsg := fmt.Sprintf("getJwtCookieFromF5 failed to get jwt token user: %s, does not exist in DB", login)
			s.Logger.Warn(myErrMsg)
			return ctx.JSON(http.StatusUnauthorized, map[string]string{"status": myErrMsg})
		}
	}
}

func (s Service) getJwtTokenFromF5AsJS(ctx echo.Context) error {
	s.Logger.TraceHttpRequest("getJwtTokenFromF5AsJS", ctx.Request())
	err := validateHostAllowed(ctx.Request(), s.AllowedHostnames, s.Logger)
	if err != nil {
		errMsg := fmt.Sprintf("error validating host: %v", err)
		s.Logger.Error(errMsg)
		return ctx.JSON(http.StatusUnauthorized, errMsg)
	}
	// get the user from the F5 Header UserId
	login := strings.TrimSpace(ctx.Request().Header.Get("UserId"))
	if login == "" {
		myErrMsg := "UserId F5 header missing"
		s.Logger.Warn(myErrMsg)
		jsError := fmt.Sprintf("console.error('Failed to get JWT token: %s');", myErrMsg)
		ctx.Response().Header().Set(echo.HeaderContentType, "application/javascript; charset=utf-8")
		return ctx.String(http.StatusUnauthorized, jsError)
	} else {
		s.Logger.Debug("About to check username: %s ", login)
		err := f5.ValidateLogin(login)
		if err != nil {
			errMsg := fmt.Sprintf("error validating user login: %v", err)
			s.Logger.Error(errMsg)
			return ctx.JSON(http.StatusBadRequest, errMsg)
		}
		if s.auth.AuthenticateUser(login, "nothing") {
			userInfo, err := s.server.Authenticator.GetUserInfoFromLogin(login)
			if err != nil {
				myErrMsg := fmt.Sprintf("Error getting user info from login: %v", err)
				s.Logger.Error(myErrMsg)
				// On error, you can return JS that logs an error
				jsError := fmt.Sprintf("console.error('Failed to get JWT token: %s');", myErrMsg)
				ctx.Response().Header().Set(echo.HeaderContentType, "application/javascript; charset=utf-8")
				return ctx.String(http.StatusInternalServerError, jsError)
			}
			token, err := s.server.JwtCheck.GetTokenFromUserInfo(userInfo)
			if err != nil {
				myErrMsg := fmt.Sprintf("Error getting jwt token from user info: %v", err)
				s.Logger.Error(myErrMsg)
				jsError := fmt.Sprintf("console.error('Failed to get JWT token: %s');", myErrMsg)
				ctx.Response().Header().Set(echo.HeaderContentType, "application/javascript; charset=utf-8")
				return ctx.String(http.StatusInternalServerError, jsError)
			}

			s.Logger.Info("LoginUser(%s) successful login", login)
			// Prepare the JavaScript code as a string
			sessionKey := fmt.Sprintf("%s_goapi_jwt_session_token", version.APP)
			jsCode := fmt.Sprintf("sessionStorage.setItem(%s, '%s'); console.log('JWT token has been stored.');", sessionKey, token.String())
			// Set the correct Content-Type header and send the string
			ctx.Response().Header().Set(echo.HeaderContentType, "application/javascript; charset=utf-8")
			return ctx.String(http.StatusOK, jsCode)
		} else {
			myErrMsg := "Error getting jwt token user does not exist in DB"
			s.Logger.Error(myErrMsg)
			jsError := fmt.Sprintf("console.error('Failed to get JWT token: %s');", myErrMsg)
			ctx.Response().Header().Set(echo.HeaderContentType, "application/javascript; charset=utf-8")
			return ctx.String(http.StatusUnauthorized, jsError)
		}
	}
}

// login is just a trivial stupid example to test this server
// you should use the jwt token returned from LoginUser  in github.com/lao-tseu-is-alive/go-cloud-k8s-user-group'
// and share the same secret with the above component
func (s Service) login(ctx echo.Context) error {
	s.Logger.TraceHttpRequest("login", ctx.Request())
	err := validateHostAllowed(ctx.Request(), s.AllowedHostnames, s.Logger)
	if err != nil {
		errMsg := fmt.Sprintf("error validating host: %v", err)
		s.Logger.Error(errMsg)
		return ctx.JSON(http.StatusUnauthorized, errMsg)
	}
	uLogin := new(UserLogin)
	login := ctx.FormValue("login")
	passwordHash := ctx.FormValue("hashed")
	s.Logger.Debug("login: %s, hash: %s ", login, passwordHash)
	// maybe it was not a form but a fetch data post
	if len(strings.Trim(login, " ")) < 1 {
		if err := ctx.Bind(uLogin); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid user login or json format in request body")
		}
	} else {
		uLogin.Username = login
		uLogin.PasswordHash = passwordHash
	}
	err = f5.ValidateLogin(uLogin.Username)
	if err != nil {
		errMsg := fmt.Sprintf("error validating user login: %v", err)
		s.Logger.Error(errMsg)
		return ctx.JSON(http.StatusInternalServerError, errMsg)
	}
	err = f5.ValidatePasswordHash(uLogin.PasswordHash)
	if err != nil {
		errMsg := fmt.Sprintf("error validating password hash: %v", err)
		s.Logger.Error(errMsg)
		return ctx.JSON(http.StatusInternalServerError, errMsg)
	}
	s.Logger.Debug("About to check username: %s , password: %s", uLogin.Username, uLogin.PasswordHash)
	if s.server.Authenticator.AuthenticateUser(uLogin.Username, uLogin.PasswordHash) {
		userInfo, err := s.server.Authenticator.GetUserInfoFromLogin(login)
		if err != nil {
			errGetUInfFromLogin := fmt.Sprintf("Error getting user info from login: %v", err)
			s.Logger.Error(errGetUInfFromLogin)
			return ctx.JSON(http.StatusInternalServerError, errGetUInfFromLogin)
		}
		token, err := s.server.JwtCheck.GetTokenFromUserInfo(userInfo)
		if err != nil {
			errGetUInfFromLogin := fmt.Sprintf("Error getting jwt token from user info: %v", err)
			s.Logger.Error(errGetUInfFromLogin)
			return ctx.JSON(http.StatusInternalServerError, errGetUInfFromLogin)
		}
		// Prepare the response
		response := map[string]string{
			"token": token.String(),
		}
		s.Logger.Info("LoginUser(%s) successful login", login)
		return ctx.JSON(http.StatusOK, response)
	} else {
		return ctx.JSON(http.StatusUnauthorized, "username not found or password invalid")
	}
}

func (s Service) GetStatus(ctx echo.Context) error {
	s.Logger.TraceHttpRequest("GetStatus", ctx.Request())
	err := validateHostAllowed(ctx.Request(), s.AllowedHostnames, s.Logger)
	if err != nil {
		errMsg := fmt.Sprintf("error validating host: %v", err)
		s.Logger.Error(errMsg)
		return ctx.JSON(http.StatusUnauthorized, errMsg)
	}
	// get the current user from JWT TOKEN
	claims := s.server.JwtCheck.GetJwtCustomClaimsFromContext(ctx)
	currentUserId := claims.User.UserId
	currentUserLogin := claims.User.Login
	s.Logger.Info("in GetStatus : currentUserId: %d", currentUserId)
	// you can check if the user is not active anymore and RETURN 401 Unauthorized
	if !s.Store.Exist(currentUserLogin) {
		return echo.NewHTTPError(http.StatusUnauthorized, "current calling user does not exist")
	}
	return ctx.JSON(http.StatusOK, claims)
}

func main() {
	l, err := golog.NewLogger("zap", golog.DebugLevel, version.APP)
	if err != nil {
		log.Fatalf("💥💥 error log.NewLogger error: %v'\n", err)
	}
	l.Info("🚀🚀 Starting:'%s', v%s, rev:%s, build:%v from: %s", version.APP, version.VERSION, version.REVISION, version.BuildStamp, version.REPOSITORY)

	dbDsn := config.GetPgDbDsnUrlFromEnvOrPanic(defaultDBIp, defaultDBPort, tools.ToSnakeCase(version.APP), version.AppSnake, defaultDBSslMode)
	db, err := database.GetInstance("pgx", dbDsn, runtime.NumCPU(), l)
	if err != nil {
		l.Fatal("💥💥 error doing database.GetInstance(pgx ...) error: %v", err)
	}
	defer db.Close()

	dbVersion, err := db.GetVersion()
	if err != nil {
		l.Fatal("💥💥 error doing dbConn.GetVersion() error: %v", err)
	}
	l.Info("connected to db version : %s", dbVersion)

	// checking metadata information
	metadataService := metadata.Service{Log: l, Db: db}
	metadataService.CreateMetadataTableOrFail()
	found, ver := metadataService.GetServiceVersionOrFail(version.APP)
	if found {
		l.Info("service %s was found in metadata with version: %s", version.APP, ver)
	} else {
		l.Info("service %s was not found in metadata", version.APP)
	}
	metadataService.SetServiceVersionOrFail(version.APP, version.VERSION)

	// Get the ENV JWT_AUTH_URL value
	jwtAuthUrl := config.GetJwtAuthUrlFromEnvOrPanic()

	myVersionReader := goHttpEcho.NewSimpleVersionReader(
		version.APP,
		version.VERSION,
		version.REPOSITORY,
		version.REVISION,
		version.BuildStamp,
		jwtAuthUrl,
	)
	// Create a new JWT checker
	myJwt := goHttpEcho.NewJwtChecker(
		config.GetJwtSecretFromEnvOrPanic(),
		config.GetJwtIssuerFromEnvOrPanic(),
		version.APP,
		config.GetJwtContextKeyFromEnvOrPanic(),
		config.GetJwtDurationFromEnvOrPanic(60),
		l)
	allowedHosts := config.GetAllowedHostsFromEnvOrPanic()
	myF5Store := f5.GetStorageInstanceOrPanic("pgx", db, l)
	// Create a new Authenticator with a F5
	myAuthenticator := f5.NewF5Authenticator(
		&goHttpEcho.UserInfo{
			UserId:     config.GetAdminIdFromEnvOrPanic(defaultAdminId),
			ExternalId: config.GetAdminExternalIdFromEnvOrPanic(99999),
			Name:       "NewSimpleAdminAuthenticator_Admin",
			Email:      config.GetAdminEmailFromEnvOrPanic(defaultAdminEmail),
			Login:      config.GetAdminUserFromEnvOrPanic(defaultAdminUser),
			IsAdmin:    false,
			Groups:     []int{1}, // this is the group id of the global_admin group
		},
		config.GetAdminPasswordFromEnvOrPanic(),
		myJwt,
		myF5Store,
	)

	server := goHttpEcho.CreateNewServerFromEnvOrFail(
		defaultPort,
		"0.0.0.0", // defaultServerIp,
		&goHttpEcho.Config{
			ListenAddress: "",
			Authenticator: myAuthenticator,
			JwtCheck:      myJwt,
			VersionReader: myVersionReader,
			Logger:        l,
			WebRootDir:    defaultWebRootDir,
			Content:       content,
			RestrictedUrl: defaultRestrictedUrlBasePath,
		},
	)
	cookieNameForJWT := GetJwtCookieNameFromEnv(defaultJwtCookieName)
	myF5Service := Service{
		AllowedHostnames: allowedHosts,
		Logger:           l,
		Store:            myF5Store,
		dbConn:           db,
		server:           server,
		auth:             myAuthenticator,
		jwtCookieName:    cookieNameForJWT,
	}

	e := server.GetEcho()
	e.Use(cookieToHeaderMiddleware(myF5Service.jwtCookieName))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"https://golux.lausanne.ch", "http://localhost:3000"},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
	}))
	e.GET("/readiness", server.GetReadinessHandler(func(info string) bool {
		ver, err := db.GetVersion()
		if err != nil {
			l.Error("Error getting db version : %v", err)
			return false
		}
		l.Info("Connected to DB version : %s", ver)
		return true
	}, "Connection to DB"))
	e.GET("/health", server.GetHealthHandler(func(info string) bool {
		// you decide what makes you ready, may be it is the connection to the database
		getVersion, err := db.GetVersion()
		if err != nil {
			l.Error("Error getting db version : %v", err)
			return false
		}
		l.Info("%s DB version : %s", info, getVersion)
		return true
	}, "Connection to DB"))

	e.GET("/goAppInfo", server.GetAppInfoHandler())
	e.POST(jwtAuthUrl, myF5Service.login)
	//curl -v -H "UserId: YOUR_F5_USER" -c cookies.txt http://localhost:8787/goLogin
	//curl -v -b cookies.txt http://localhost:8787/goapi/v1/status|jq
	// or if you have a token stored in $TOKEN
	//curl -v -b "yourOwnJwtCookieName=${TOKEN}"  http://localhost:8787/goapi/v1/status
	e.GET(jwtAuthUrl, myF5Service.getJwtCookieFromF5)
	r := server.GetRestrictedGroup()
	r.GET("/status", myF5Service.GetStatus)

	err = server.StartServer()
	if err != nil {
		l.Fatal("💥💥 error doing server.StartServer error: %v'\n", err)
	}
}
