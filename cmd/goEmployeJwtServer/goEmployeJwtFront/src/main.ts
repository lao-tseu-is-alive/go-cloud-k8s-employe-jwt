/**
 * main.ts
 *
 * Bootstraps Vuetify and other plugins then mounts the App`
 */

// Composables
import { createApp } from "vue";

// Plugins
import { registerPlugins } from "@/plugins";
import { createPinia } from "pinia";
// Components
// App
import App from "./App.vue";

const app = createApp(App);

registerPlugins(app);
app.use(createPinia());

app.mount("#app");
