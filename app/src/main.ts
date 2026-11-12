import "@fontsource-variable/inter";
import "./styles.css";
import { h } from "./dom";
import { errText, type Ctx, type ViewHandle } from "./context";
import { icon } from "./icons";
import { createQr } from "./qr";
import { initScale } from "./scale";
import { initTheme } from "./theme";
import { createTauriApi, isTauri } from "./tauri";
import { createStore, initialState, LIVE_POINTS, pushLive } from "./store";
import type { View } from "./types";
import { toast } from "./ui";
import { createActivity } from "./views/activity";
import { createDevices } from "./views/devices";
import { createHotspot } from "./views/hotspot";
import { createSettings } from "./views/settings";

const VIEWS: View[] = ["devices", "activity", "settings"];
/** Onglets du quotidien ; les réglages avancés sont derrière l'engrenage. */
const TABS: Array<{ view: View; label: string }> = [
  { view: "devices", label: "Appareils" },
  { view: "activity", label: "Activité" },
];

async function boot(): Promise<void> {
  const root = document.getElementById("app");
  if (!root) return;
  const params = new URLSearchParams(location.search);
  if (params.has("still")) document.documentElement.classList.add("still");
  // Thème posé avant tout rendu : pas de flash clair en mode sombre.
  initTheme();
  // Captures de la maquette : `?theme=dark` force le thème sombre.
  if (params.get("theme") === "dark") document.documentElement.dataset.theme = "dark";

  // Dans l'app : le vrai moteur. Dans un navigateur : la maquette, chargée à la demande
  // pour ne pas être embarquée dans l'app.
  const mock = isTauri() ? null : await import("./mock");
  const api = mock ? mock.createMockApi(params) : await createTauriApi();
  initScale(api);
  const store = createStore(initialState(VIEWS.find((v) => v === params.get("view")) ?? "devices"));
  if (mock && params.get("mock") !== "off") store.set({ live: mock.seedLive(LIVE_POINTS) });

  const qr = createQr();
  const win = h("div", { class: "window" });
  /** Onglet à retrouver en quittant les réglages. */
  let previous: View = "devices";
  const ctx: Ctx = {
    api,
    store,
    notify: (message, kind = "info") => toast(win, message, kind),
    openQr: () => {
      const s = store.get().snapshot;
      if (s) qr.open(s.ssid, s.passphrase);
    },
    go: (view) => {
      const cur = store.get().view;
      if (view === "settings" && cur !== "settings") previous = cur;
      store.set({ view });
    },
  };

  // En réglages, l'en-tête de l'espace de travail affiche la page ouverte.
  const workTitle = h("span", { class: "work-title" }, "Réglages");
  const views: Record<View, ViewHandle> = {
    devices: createDevices(ctx),
    activity: createActivity(ctx),
    settings: createSettings(ctx, { setTitle: (t) => { workTitle.textContent = t; } }),
  };

  // --- Barre de titre ---
  const minimize = h("button", { class: "tb-win", type: "button", "aria-label": "Réduire" }, icon("minimize", 16));
  const close = h("button", { class: "tb-win tb-close", type: "button", "aria-label": "Fermer" }, icon("close", 16));
  minimize.addEventListener("click", () => api.minimize());
  close.addEventListener("click", () => api.hide());
  const titlebar = h("header", { class: "titlebar", "data-tauri-drag-region": true },
    h("span", { class: "app-name" }, h("span", { class: "app-mark" }, icon("wifi", 13)), "axios"),
    h("div", { class: "tb-right" }, minimize, close));

  // --- Espace de travail ---
  const tabs = new Map<View, HTMLButtonElement>();
  const count = h("span", { class: "tab-count mono" });
  const gear = h("button", { class: "icon-btn work-gear", type: "button", "aria-label": "Réglages", title: "Réglages" }, icon("settings", 16));
  gear.addEventListener("click", () => ctx.go("settings"));
  const tabBar = h("nav", { class: "work-tabs", "aria-label": "Sections" }, ...TABS.map((t) => {
    const b = h("button", { class: "work-tab", type: "button" }, t.label);
    if (t.view === "devices") b.append(count);
    b.addEventListener("click", () => ctx.go(t.view));
    tabs.set(t.view, b);
    return b;
  }), h("span", { class: "grow" }), gear);

  // En réglages : un titre et un retour à la place des onglets.
  const back = h("button", { class: "icon-btn", type: "button", "aria-label": "Retour", title: "Retour" }, icon("arrowLeft", 16));
  // Retour : d'abord la sous-page des réglages, puis l'onglet d'où l'on venait.
  back.addEventListener("click", () => {
    if (!views.settings.back?.()) ctx.go(previous);
  });
  const settingsBar = h("header", { class: "work-tabs work-head" }, back, workTitle);

  const body = h("div", { class: "work-body" }, ...VIEWS.map((v) => views[v].el));
  const work = h("section", { class: "work" }, tabBar, settingsBar, body);

  win.append(titlebar, h("div", { class: "split" }, createHotspot(ctx), work), qr.el);
  root.append(win);

  let shown: View | null = null;
  store.subscribe((s) => {
    for (const [view, b] of tabs) b.setAttribute("aria-current", view === s.view ? "page" : "false");
    const n = s.stats.devices.length;
    count.hidden = n === 0;
    count.textContent = String(n);
    if (s.view === shown) return;
    shown = s.view;
    tabBar.hidden = s.view === "settings";
    settingsBar.hidden = s.view !== "settings";
    for (const v of VIEWS) views[v].el.hidden = v !== s.view;
    body.scrollTop = 0;
    views[s.view].shown?.();
  });

  api.onSnapshot((snapshot) => store.set({ snapshot }));
  api.onStats((stats) => store.set({ stats, live: pushLive(store.get().live, stats.rateDown, stats.rateUp) }));
  try {
    const [snapshot, settings, sources] = await Promise.all([api.getSnapshot(), api.getSettings(), api.getSources()]);
    store.set({ snapshot, settings, sources });
  } catch (e) {
    ctx.notify(errText(e), "error");
  }

  if (params.has("qr")) ctx.openQr();
}

void boot();
