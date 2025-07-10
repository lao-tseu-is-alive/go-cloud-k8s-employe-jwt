<style>
.full-width {
  width: 100%;
  max-width: unset !important;
}

.info {
  color: #1976d2;
}

.trace {
  color: #3d873f;
}

.warn {
  color: #ff9800;
}

.error {
  color: #f44336;
}
</style>
<template>
  <v-app>
    <v-app-bar app color="primary" dark>
      <v-toolbar-title
        >{{ appStore.getAppName }} v{{
          appStore.getAppVersion
        }}</v-toolbar-title
      >
      <template v-if="appStore.getIsUserAuthenticated">
        <v-btn v-if="DEV" @click="showDebug = !showDebug"
          >{{ showDebug ? "Hide Debug" : "Show Debug" }}
        </v-btn>
        <v-spacer />

        <v-btn
          variant="text"
          icon="mdi-logout"
          title="Logout"
          @click="logout"
        ></v-btn>
      </template>
    </v-app-bar>

    <template v-if="appStore.getIsUserAuthenticated">
      <v-main>
        <v-snackbar
          v-model="appStore.feedbackVisible"
          :timeout="appStore.feedbackTimeout"
          rounded="pill"
          :color="appStore.feedbackType"
          location="top"
        >
          <v-alert
            class="ma-4"
            :type="appStore.feedbackType"
            :text="appStore.feedbackMsg"
            :color="appStore.feedbackType"
          ></v-alert>
        </v-snackbar>
        <v-container class="w-100 full-width full-height">
          <v-card>
            <v-card-title>Connected</v-card-title>
            <v-card-text>
              token:
              {{appStore.getUserJwtToken}}
              user:
              {{getUserId(appStore.getAppName)}}
            </v-card-text>

          </v-card>
        </v-container>
      </v-main>
    </template>
    <template v-else>
      <Login
        :app="appStore.getAppName"
        :base_server_url="BACKEND_URL"
        :jwt_auth_url="appStore.getAppAuthUrl"
        @login-ok="handleLoginSuccess"
        @login-error="handleLoginFailure"
      />
    </template>
  </v-app>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { BACKEND_URL, DEV, getLog, HOME } from "@/config";
import Login from "@/components/Login.vue";
import { useAppStore } from "@/stores/appStore";
import {
  doesCurrentSessionExist,
  getTokenStatus,
  getUserId,
  logoutAndResetToken,
} from "@/components/AuthService";
import { isNullOrUndefined } from "@/tools/utils";

let log = getLog("APP", 4, 2);
const appStore = useAppStore();
const showDebug = ref(false);

const defaultFeedbackErrorTimeout = 5000; // default display time 5sec
let autoLogoutTimer: number;

const logout = () => {
  log.t("# IN logout()");
  logoutAndResetToken(appStore.getAppName, BACKEND_URL);
  appStore.setUserNotAuthenticated();
  appStore.displayFeedBack(
    "Vous vous êtes déconnecté de l'application avec succès !",
    "success",
  );
  if (isNullOrUndefined(autoLogoutTimer)) {
    clearInterval(autoLogoutTimer);
  }
  setTimeout(() => {
    window.location.href = HOME;
  }, 2000); // after 2 sec redirect to home page just in case
};

const checkIsSessionTokenValid = () => {
  log.t(`# entering...  ${appStore.getAppName}`);
  if (doesCurrentSessionExist(appStore.getAppName)) {
    getTokenStatus(appStore.getAppName, BACKEND_URL)
      .then((val) => {
        if (val.data == null) {
          log.e(`# getTokenStatus() ${val.msg}, ERROR is: `, val.err);
          appStore.displayFeedBack(
            `Problème réseau :${val.msg}`,
            "error",
            defaultFeedbackErrorTimeout,
          );
          logout();
        } else {
          log.l(`# getTokenStatus() SUCCESS ${val.msg} data: `, val.data);
          if (isNullOrUndefined(val.err) && val.status === 200) {
            // everything is okay, session is still valid
            appStore.setUserAuthenticated();
            return;
          }
          if (val.status === 401) {
            // jwt token is no more valid
            appStore.setUserNotAuthenticated();
            appStore.displayFeedBack(
              "Votre session a expiré !",
              "warning",
              defaultFeedbackErrorTimeout,
            );
            logout();
          }
          appStore.displayFeedBack(
            `Un problème est survenu avec votre session erreur: ${val.err}`,
            "error",
            defaultFeedbackErrorTimeout,
          );
        }
      })
      .catch((err) => {
        log.e("# getJwtToken() in catch ERROR err: ", err);
        appStore.displayFeedBack(
          `Il semble qu'il y a eu un problème réseau ! erreur: ${err}`,
          "error",
          defaultFeedbackErrorTimeout,
        );
      });
  } else {
    log.w("SESSION DOES NOT EXIST OR HAS EXPIRED !");
    logout();
  }
};

const handleLoginSuccess = async (v: string) => {
  log.t(`# entering... val:${v} `);
  appStore.setUserAuthenticated();
  appStore.hideFeedBack();
  appStore.displayFeedBack(
    "Vous êtes authentifié sur l'application.",
    "success",
  );

  log.l(`appStore.getUserJwtToken :   ${appStore.getUserJwtToken}`);

  if (isNullOrUndefined(autoLogoutTimer)) {
    // check every 60 seconds(60'000 milliseconds) if jwt is still valid
    autoLogoutTimer = window.setInterval(checkIsSessionTokenValid, 60000);
  }
};

const handleLoginFailure = (v: string) => {
  log.w(`# entering... val:${v} `);
  appStore.setUserNotAuthenticated();
  appStore.hideFeedBack();
};

onMounted(async () => {
  log.t(`onMounted Main App.vue ${BACKEND_URL}`);
  try {
    await appStore.fetchAppInfo();
    log.l(
      `App.vue ${appStore.getAppName} v${appStore.getAppVersion}, from ${appStore.getAppRepository}`,
    );
  } catch (error) {
    log.e("Error fetching app info:", error);
  }
});
</script>
