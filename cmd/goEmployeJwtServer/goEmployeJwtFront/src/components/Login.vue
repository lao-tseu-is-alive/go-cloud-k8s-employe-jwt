<template>
  <v-container class="fluid fill-height">
    <v-responsive class="d-flex align-center text-center fill-height">
      <v-row class="d-flex align-center justify-center">
        <v-col cols="auto">
          <v-card class="mx-auto elevation-12" min-width="345">
            <v-toolbar density="compact" dark color="primary">
              <v-toolbar-title>{{ app }}</v-toolbar-title>
            </v-toolbar>
            <v-card-text>
              <v-form ref="login-form" v-model="validLoginForm" lazy-validation>
                <v-text-field
                  id="username"
                  name="username"
                  ref="username"
                  v-model="username"
                  required
                  autocomplete="username"
                  prepend-icon="mdi-account"
                  cleareable
                  hide-details="auto"
                  :rules="[() => !!username || 'Veuillez saisir votre login, il est obligatoire']"
                  @keyup.enter="onEnterKey"
                  label="Utilisateur"
                  hint="Entrez votre utilisateur"
                  type="text"
                >
                </v-text-field>
                <v-text-field
                  id="password"
                  name="password"
                  ref="password"
                  v-model="password"
                  required
                  autocomplete="current-password"
                  prepend-icon="mdi-key"
                  :rules="[() => !!password || 'Veuillez saisir votre mot de passe, il est obligatoire']"
                  label="Mot de passe"
                  hint="Veuillez saisir votre mot de passe"
                  :append-inner-icon="showPassword ? 'mdi-eye-off' : 'mdi-eye'"
                  @click:append-inner="showPassword = !showPassword"
                  @keyup.enter="onEnterKey"
                  :type="showPassword ? 'text' : 'password'"
                >
                </v-text-field>
                <template v-if="feedbackVisible">
                  <v-icon color="red" icon="mdi-alert-circle"></v-icon>
                  <v-label class="pl-1" :value="feedbackVisible" :color="feedbackType" :icon="feedbackType" outlined>
                    {{ feedbackText }}
                  </v-label>
                </template>
              </v-form>
            </v-card-text>
            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn dark color="primary" variant="flat" prepend-icon="mdi-location-enter" @click.prevent="getJwtToken"
                >Connexion</v-btn
              >
            </v-card-actions>
          </v-card>
        </v-col>
      </v-row>
    </v-responsive>
  </v-container>
</template>

<script>
import { isNullOrUndefined } from "@/tools/utils"
import { BACKEND_URL, getLog } from "@/config"
import {getToken, getPasswordHashSHA256} from "@/components/AuthService";

const log = getLog("Login-Vue", 4, 2)


export default {
  name: "LoginVue",
  data: () => ({
    drawer: null,
    username: null,
    password: null,
    showPassword: false,
    validLoginForm: false,
    feedbackVisible: false,
    feedbackText: "Veuillez vous authentifier SVP.",
    feedbackType: "info",
  }),

  props: {
    base_server_url: {
      type: String,
      default: BACKEND_URL,
    },
    app: {
      type: String,
      default: "APP",
    },
    jwt_auth_url: {
      type: String,
    },
  },

  mounted() {
    log.t("# IN mounted()")
    this.$refs.username.focus()
  }, // end of mounted
  methods: {
    onEnterKey() {
      log.t("# IN onEnterKey()")
      if (this.username.trim().length < 1) {
        this.displayFeedBack("Veuillez saisir votre utilisateur, il est obligatoire!")
        this.$refs.username.focus()
        return false
      }
      if (this.password.trim().length < 1) {
        this.displayFeedBack("Veuillez saisir votre mot de passe, il est obligatoire!")
        return false
      }
      this.getJwtToken()
      return true
    },
    displayFeedBack(text, type) {
      this.feedbackText = text
      this.feedbackType = type
      this.feedbackVisible = true
    },
    resetFeedBack() {
      this.feedbackText = ""
      this.feedbackType = "info"
      this.feedbackVisible = false
    },
    getJwtToken: async function () {
      log.t("# IN getJwtToken()")
      this.resetFeedBack()
      if (await this.$refs["login-form"].validate()) {
        try {
          const hash = await getPasswordHashSHA256(this.password)
          log.l(`password hash: ${hash}`) // Await the hash
          const res = getToken(this.app, this.base_server_url, this.jwt_auth_url, this.username, hash)
            .then((val) => {
              if (val.data == null) {
                if (!isNullOrUndefined(val.err)) {
                  log.w(`# getJwtToken() ${val.msg}, ERROR is: `, val.err)
                  this.displayFeedBack(`Le serveur est inaccessible : ${val.err}`, "error")
                } else {
                  log.w(`# getToken received status ${val.status}`, val)
                  this.displayFeedBack("Vos informations de connexions sont erronées !", "warning")
                }
                this.$emit("loginError", "LOGIN FAILED", val.err)
              } else {
                log.l("# getJwtToken() SUCCESS val.data: ", val.data)
                this.$emit("login-ok", "LOGIN SUCCESS")
              }
            })
            .catch((err) => {
              log.e("# getJwtToken() in catch ERROR err: ", err)
              this.displayFeedBack(`Il semble qu'il y a un problème de réseau !${err}`, "error")
              this.$emit("loginError", "LOGIN ERROR", err)
            })
          log.l("# getJwtToken() after getToken res:", res)
        } catch (e) {
          log.t("# getJwtToken() TRY CATCH ERROR : ", e)
        }
      } else if (this.username.trim().length < 1) {
        this.displayFeedBack("Veuillez saisir votre utilisateur, il est obligatoire!")
      } else if (this.password.trim().length < 1) {
        this.displayFeedBack("Veuillez saisir votre mot de passe, il est obligatoire!")
      }
      log.t("# GOING OUT getJwtToken()")
    },
  },
}
</script>
