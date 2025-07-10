import axios from "axios";
import { getLog, BACKEND_URL, defaultAxiosTimeout } from "@/config";

// Logger setup
const log = getLog("AuthService", 2, 1);

// Centralized session storage keys
const SESSION_KEYS = {
  JWT_TOKEN: "_goapi_jwt_session_token",
  USER_ID: "_goapi_idgouser",
  USER_EXTERNAL_ID: "_goapi_user_external_id",
  NAME: "_goapi_name",
  USERNAME: "_goapi_username",
  EMAIL: "_goapi_email",
  IS_ADMIN: "_goapi_isadmin",
  DATE_EXPIRATION: "_goapi_date_expiration",
  SESSION_UUID: "_goapi_session_uuid",
  GROUPS: "_goapi_groups",
} as const;

// Custom error class for authentication errors
class AuthError extends Error {
  constructor(
    message: string,
    public status?: number,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

// Interface for the JWT payload from the backend
interface JwtPayload {
  User: {
    user_id: number;
    external_id: string;
    login: string;
    email: string;
    is_admin: boolean;
  };
  name: string;
  exp: number;
}

// Interface for the user profile data
interface UserProfile {
  jwtToken: string;
  userId: number;
  userExternalId: string;
  name: string;
  username: string;
  email: string;
  isAdmin: boolean;
  dateExpiration: number;
  sessionUuid: string;
  groups: string | null;
}

// Session storage utilities
const getSessionKey = (appName: string, key: string): string =>
  `${appName}${key}`;

const setSessionItem = (appName: string, key: string, value: string): void => {
  sessionStorage.setItem(getSessionKey(appName, key), value);
};

const getSessionItem = (appName: string, key: string): string | null => {
  log.t(
    `session get called with key:${key}, appName:${getSessionKey(appName, key)}`,
  );
  return sessionStorage.getItem(getSessionKey(appName, key));
};

const removeSessionItem = (appName: string, key: string): void => {
  sessionStorage.removeItem(getSessionKey(appName, key));
};

const clearSession = (appName: string): void => {
  Object.values(SESSION_KEYS).forEach((key) => removeSessionItem(appName, key));
  log.t("Session storage cleared for app:", appName);
};

// Parses a JWT token to extract its payload
const parseJwt = (token: string): JwtPayload => {
  try {
    const base64Url = token.split(".")[1];
    if (!base64Url) throw new Error("Invalid JWT format: Missing payload.");

    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      window
        .atob(base64)
        .split("")
        .map((c) => `%${`00${c.charCodeAt(0).toString(16)}`.slice(-2)}`)
        .join(""),
    );
    return JSON.parse(jsonPayload) as JwtPayload;
  } catch (error) {
    log.e("Error parsing JWT:", error);
    throw new AuthError(
      `Invalid JWT token: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};

export const getPasswordHashSHA256 = async (password:string, minLength:number = 8) => {
  if (password.trim().length >= minLength) {
    const encoder = new TextEncoder()
    const data = encoder.encode(password)
    const hashBuffer = await crypto.subtle.digest("SHA-256", data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("")
  } else {
    throw new AuthError(`Password must be at least ${minLength} characters long`)
  }
}

// Authenticates a user and saves the session
export const getToken = async (
  appName: string,
  baseServerUrl: string,
  jwtAuthUrl: string,
  username: string,
  passwordHash: string,
): Promise<{
  msg: string;
  err: Error | null;
  status: number | undefined;
  data: any;
}> => {
  if (!appName?.trim() || !username?.trim() || !passwordHash?.trim()) {
    throw new AuthError("appName, username, and passwordHash are required");
  }

  const loginUrl = `${baseServerUrl}${jwtAuthUrl}`;
  log.t(`# entering getToken... ${loginUrl} data:`, { username });

  try {
    const response = await axios.post(loginUrl, {
      username,
      password_hash: passwordHash,
    });
    log.l("getToken() axios.post Success! response:", response.data);

    const jwtValues = parseJwt(response.data.token);
    log.l("getToken() parsed token values:", jwtValues);

    const dExpires = new Date(0);
    dExpires.setUTCSeconds(jwtValues.exp);
    log.l(`getToken() JWT token expiration: ${dExpires}`);

    // Store all values in session storage
    setSessionItem(appName, SESSION_KEYS.JWT_TOKEN, response.data.token);
    if (response.data.session) {
      setSessionItem(appName, SESSION_KEYS.SESSION_UUID, response.data.session);
    }
    setSessionItem(
      appName,
      SESSION_KEYS.USER_ID,
      String(jwtValues.User.user_id),
    );
    setSessionItem(
      appName,
      SESSION_KEYS.USER_EXTERNAL_ID,
      jwtValues.User.external_id,
    );
    setSessionItem(appName, SESSION_KEYS.NAME, jwtValues.name);
    setSessionItem(appName, SESSION_KEYS.USERNAME, jwtValues.User.login);
    setSessionItem(appName, SESSION_KEYS.EMAIL, jwtValues.User.email);
    setSessionItem(
      appName,
      SESSION_KEYS.IS_ADMIN,
      String(jwtValues.User.is_admin),
    );
    setSessionItem(
      appName,
      SESSION_KEYS.DATE_EXPIRATION,
      String(jwtValues.exp),
    );

    return {
      msg: "getToken() axios.post Success.",
      err: null,
      status: response.status,
      data: response.data,
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const msg = `getToken() Axios Error: ${error.message}`;
      log.w(msg, error.response);
      return { msg, err: error, status: error.response?.status, data: null };
    }
    const msg = `getToken() Unexpected Error: ${error}`;
    log.e(msg);
    return {
      msg,
      err: error instanceof Error ? error : new Error(String(error)),
      status: undefined,
      data: null,
    };
  }
};

// Retrieves and validates the user profile
export const getUserProfile = (appName: string): UserProfile | null => {
  log.t("# entering getUserProfile validation...");

  const jwtToken = getSessionItem(appName, SESSION_KEYS.JWT_TOKEN);
  const expiration = getSessionItem(appName, SESSION_KEYS.DATE_EXPIRATION);
  const userId = getSessionItem(appName, SESSION_KEYS.USER_ID);
  const email = getSessionItem(appName, SESSION_KEYS.EMAIL);

  if (!jwtToken || !expiration || !userId || !email) {
    log.w(
      `# IN getUserProfile() - Missing required session keys: jwtToken: ${jwtToken}, expiration: ${expiration}, userId: ${userId}, email: ${email}`,
    );
    return null;
  }

  const dateExpire = new Date(parseInt(expiration, 10) * 1000);
  const now = new Date();

  if (now > dateExpire) {
    log.w(
      `# IN getUserProfile() - SESSION EXPIRED. Expiration was: ${dateExpire.toString()}`,
    );
    clearSession(appName);
    return null;
  }

  const minutesUntilExpire = Math.floor(
    (dateExpire.getTime() - now.getTime()) / 1000 / 60,
  );
  log.l(
    `Yes, session exists and is valid for ${minutesUntilExpire} more minutes.`,
  );

  return {
    jwtToken,
    dateExpiration: parseInt(expiration, 10),
    userId: parseInt(userId, 10),
    email,
    isAdmin: getSessionItem(appName, SESSION_KEYS.IS_ADMIN) === "true",
    name: getSessionItem(appName, SESSION_KEYS.NAME) ?? "",
    username: getSessionItem(appName, SESSION_KEYS.USERNAME) ?? "",
    userExternalId:
      getSessionItem(appName, SESSION_KEYS.USER_EXTERNAL_ID) ?? "",
    sessionUuid: getSessionItem(appName, SESSION_KEYS.SESSION_UUID) ?? "",
    groups: getSessionItem(appName, SESSION_KEYS.GROUPS),
  };
};

// Checks if a valid session exists
export const doesCurrentSessionExist = (appName: string): boolean => {
  log.t("# entering doesCurrentSessionExist...");
  return getUserProfile(appName) !== null;
};

// Checks the status of the current JWT token on the server
export const getTokenStatus = async (
  appName: string,
  baseServerUrl = BACKEND_URL,
): Promise<{
  msg: string;
  err: Error | null;
  status: number | undefined;
  data: any;
}> => {
  log.t("# entering getTokenStatus...");
  const profile = getUserProfile(appName);
  if (!profile) {
    return {
      msg: "No valid session found locally.",
      err: new AuthError("No session"),
      status: 401,
      data: null,
    };
  }

  try {
    const res = await axios.get(`${baseServerUrl}/goapi/v1/status`, {
      headers: {
        Authorization: `Bearer ${profile.jwtToken}`,
        "X-Goeland-Token": profile.sessionUuid,
      },
      timeout: defaultAxiosTimeout,
    });

    log.l("getTokenStatus() axios.get Success! response:", res);
    const dExpires = new Date(0);
    dExpires.setUTCSeconds(res.data.exp);
    const msg = `getTokenStatus() JWT token expiration: ${dExpires}`;
    log.l(msg);
    return { msg, err: null, status: res.status, data: res.data };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const msg = `Error in getTokenStatus(): ${error.message}`;
      log.w(msg, error.response);
      return { msg, err: error, status: error.response?.status, data: null };
    }
    const msg = `Unexpected error in getTokenStatus(): ${error}`;
    log.e(msg);
    return {
      msg,
      err: error instanceof Error ? error : new Error(String(error)),
      status: undefined,
      data: null,
    };
  }
};

// Logs out the user and clears the session
export const logoutAndResetToken = async (
  appName: string,
  baseServerUrl: string,
): Promise<void> => {
  log.t("# IN logoutAndResetToken()");
  const profile = getUserProfile(appName);
  clearSession(appName);

  if (!profile) {
    log.w("logoutAndResetToken called, but no local session was found.");
    return;
  }

  try {
    const response = await axios.get(`${baseServerUrl}/goapi/v1/logout`, {
      headers: { Authorization: `Bearer ${profile.jwtToken}` },
    });
    log.l("logoutAndResetToken() Server logout Success! response:", response);
  } catch (error) {
    log.e("logoutAndResetToken() ## SERVER LOGOUT ERROR ##:", error);
    throw new AuthError(
      `Server logout failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};

// User profile getters
export const getLocalJwtTokenAuth = (appName: string): string =>
  getUserProfile(appName)?.jwtToken ?? "";
export const getDateExpiration = (appName: string): number =>
  getUserProfile(appName)?.dateExpiration ?? 0;
export const getUserEmail = (appName: string): string =>
  getUserProfile(appName)?.email ?? "";
export const getUserId = (appName: string): number =>
  getUserProfile(appName)?.userId ?? 0;
export const getUserName = (appName: string): string =>
  getUserProfile(appName)?.name ?? "";
export const getUserLogin = (appName: string): string =>
  getUserProfile(appName)?.username ?? "";
export const getUserIsAdmin = (appName: string): boolean =>
  getUserProfile(appName)?.isAdmin ?? false;
export const getSessionId = (appName: string): string =>
  getUserProfile(appName)?.sessionUuid ?? "";
export const getUserGroupsArray = (appName: string): number[] | null => {
  const groups = getUserProfile(appName)?.groups;
  if (!groups || groups === "null") return null;
  return groups.split(",").map((i) => parseInt(i.trim(), 10));
};
export const getUserFirstGroups = (appName: string): number | null =>
  getUserGroupsArray(appName)?.[0] ?? null;
export const isUserHavingGroups = (appName: string): boolean => {
  const groups = getUserProfile(appName)?.groups;
  return !!groups && groups !== "null";
};
