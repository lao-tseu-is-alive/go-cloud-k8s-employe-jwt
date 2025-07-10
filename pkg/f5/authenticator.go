package f5

import (
	"crypto/sha256"
	"fmt"
	"github.com/lao-tseu-is-alive/go-cloud-k8s-common-libs/pkg/goHttpEcho"
)

type Authentication interface {
	AuthenticateUser(user, passwordHash string) bool
	GetUserInfoFromLogin(login string) (*goHttpEcho.UserInfo, error)
}

// Authenticator Create a struct that will implement the Authentication interface
type Authenticator struct {
	// You can add fields here if needed, e.g., a database connection
	mainAdminUserLogin    string
	mainAdminPasswordHash string
	mainAdminEmail        string
	mainAdminId           int
	mainAdminExternalId   int
	jwtChecker            goHttpEcho.JwtChecker
	store                 Storage
}

// AuthenticateUser Implement the AuthenticateUser method for F5Authenticator
func (sa *Authenticator) AuthenticateUser(userLogin, passwordHash string) bool {
	l := sa.jwtChecker.GetLogger()
	l.Info("userLogin: %s", userLogin)
	// check if it's the env admin user
	if userLogin == sa.mainAdminUserLogin && passwordHash == sa.mainAdminPasswordHash {
		return true
	}
	// look in db
	if sa.store.Exist(userLogin) {
		return true
	}
	sa.jwtChecker.GetLogger().Info("User %s was not authenticated", userLogin)
	return false
}

// GetUserInfoFromLogin Get the JWT claims from the login User
func (sa *Authenticator) GetUserInfoFromLogin(login string) (*goHttpEcho.UserInfo, error) {

	user := &goHttpEcho.UserInfo{
		UserId:     sa.mainAdminId,
		ExternalId: sa.mainAdminExternalId,
		Name:       fmt.Sprintf("SimpleAdminAuthenticator_%s", sa.mainAdminUserLogin),
		Email:      sa.mainAdminEmail,
		Login:      login,
		IsAdmin:    true,
		Groups:     []int{1}, // this is the group id of the global_admin group
	}
	return user, nil
}

// NewF5Authenticator Function to create an instance of F5Authenticator
func NewF5Authenticator(u *goHttpEcho.UserInfo, mainAdminPassword string, jwtCheck goHttpEcho.JwtChecker, store Storage) Authentication {
	l := jwtCheck.GetLogger()
	h := sha256.New()
	h.Write([]byte(mainAdminPassword))
	mainAdminPasswordHash := fmt.Sprintf("%x", h.Sum(nil))
	l.Info("mainAdminUserLogin: %s", u.Login)
	return &Authenticator{
		mainAdminUserLogin:    u.Login,
		mainAdminPasswordHash: mainAdminPasswordHash,
		mainAdminEmail:        u.Email,
		mainAdminId:           u.UserId,
		mainAdminExternalId:   u.ExternalId,
		jwtChecker:            jwtCheck,
		store:                 store,
	}
}
