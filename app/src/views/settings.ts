import { h } from "../dom";
import { validatePassphrase, validateSsid } from "../format";
import { errText, LIMITS, limitLabel, type Ctx, type ViewHandle } from "../context";
import { icon, type IconName } from "../icons";
import type { Dns, Settings } from "../types";
import { currentScale, onScale, SCALES, scaleLabel, setScale, type Scale } from "../scale";
import { currentTheme, onTheme, setTheme, THEME_LABEL, THEMES, type Theme } from "../theme";
import { iconButton, segmented, select, settingRow, toggle, type Option, type Toggle } from "../ui";

const DNS: Option<Dns>[] = [
  { value: "auto", label: "Automatique" },
  { value: "cloudflare", label: "Cloudflare" },
  { value: "google", label: "Google" },
  { value: "custom", label: "Personnalisé" },
];

type Page = "network" | "protection" | "advanced" | "display" | "app";

/** Entrées de la page d'accueil des réglages ; chaque page tient sans défilement. */
const PAGES: Array<{ id: Page; title: string; icon: IconName }> = [
  { id: "network", title: "Réseau", icon: "wifi" },
  { id: "protection", title: "Protection", icon: "shield" },
  { id: "advanced", title: "Avancé", icon: "gauge" },
  { id: "display", title: "Affichage", icon: "display" },
  { id: "app", title: "Application", icon: "settings" },
];

/** En-tête de l'espace de travail, piloté par les réglages (titre de la page ouverte). */
export interface SettingsHeader {
  setTitle(title: string): void;
}

export function createSettings(ctx: Ctx, header: SettingsHeader): ViewHandle {
  const { api, store } = ctx;

  // ---------- Réglages enregistrés ----------
  const toggles: Array<[keyof Settings, Toggle]> = [];
  const setting = (key: keyof Settings, label: string): HTMLElement => {
    const t = toggle(label, false, (on) => void save({ [key]: on }));
    toggles.push([key, t]);
    return t.el;
  };
  async function save(patch: Partial<Settings>): Promise<void> {
    const before = store.get().settings;
    if (!before) return;
    store.set({ settings: { ...before, ...patch } });
    try {
      store.set({ settings: await api.updateSettings(patch) });
    } catch (e) {
      store.set({ settings: before });
      ctx.notify(errText(e), "error");
    }
  }

  // ---------- Réseau ----------
  const ssid = h("input", { class: "input", type: "text", maxlength: 32, spellcheck: "false", "aria-label": "Nom du réseau" });
  const pass = h("input", { class: "input mono", type: "password", maxlength: 63, spellcheck: "false", "aria-label": "Mot de passe" });
  const eye = iconButton("eye", "Afficher le mot de passe", () => {
    const show = pass.type === "password";
    pass.type = show ? "text" : "password";
    eye.replaceChildren(icon(show ? "eyeOff" : "eye", 16));
  });
  const apply = h("button", { class: "btn btn-dark", type: "button" }, "Appliquer");
  const cancel = h("button", { class: "btn", type: "button" }, "Annuler");
  const applyRow = h("div", { class: "row row-end", hidden: true }, cancel, apply);
  const sync = (): void => {
    const s = store.get().snapshot;
    applyRow.hidden = !s || (ssid.value === s.ssid && pass.value === s.passphrase);
  };
  const reset = (): void => {
    const s = store.get().snapshot;
    if (!s) return;
    ssid.value = s.ssid;
    pass.value = s.passphrase;
    sync();
  };
  ssid.addEventListener("input", sync);
  pass.addEventListener("input", sync);
  cancel.addEventListener("click", reset);
  apply.addEventListener("click", async () => {
    const s = store.get().snapshot;
    if (!s) return;
    const invalid = validateSsid(ssid.value.trim()) ?? validatePassphrase(pass.value);
    if (invalid) return ctx.notify(invalid, "error");
    apply.disabled = true;
    try {
      await api.configureNetwork(ssid.value.trim(), pass.value, s.band);
      ctx.notify("Réseau mis à jour");
    } catch (e) {
      ctx.notify(errText(e), "error");
    } finally {
      apply.disabled = false;
      sync();
    }
  });
  const source = select<string>("Connexion partagée", [], "", async (id) => {
    try {
      await api.setSource(id);
      ctx.notify("Connexion changée");
    } catch (e) {
      ctx.notify(errText(e), "error");
    }
  }, "box");
  const sourceRow = settingRow("Connexion partagée", "Internet à partager", source.el);

  // ---------- Protection et avancé ----------
  const limit = select<string>("Débit maximal", LIMITS.map((l) => ({ value: String(l), label: limitLabel(l) })), "null",
    (v) => void save({ defaultLimit: v === "null" ? null : Number(v) }), "box");
  const dns = select<Dns>("Serveur DNS", DNS, "auto", (v) => void save({ dns: v }), "box");
  const customDns = h("input", { class: "input input-sm mono", type: "text", placeholder: "1.1.1.1", spellcheck: "false", "aria-label": "Adresse DNS" });
  customDns.addEventListener("change", () => void save({ customDns: customDns.value.trim() }));
  const customRow = settingRow("Adresse du serveur", "IPv4 du résolveur", customDns);

  /** Résumés affichés sous chaque entrée de l'accueil des réglages. */
  const summaries = new Map<Page, HTMLElement>();

  // ---------- Affichage : préférences de ce poste, appliquées tout de suite ----------
  const theme = segmented<Theme>("Thème", THEMES.map((t) => ({ value: t, label: THEME_LABEL[t] })), "system", setTheme);
  const scale = segmented<string>("Taille de l'interface",
    SCALES.map((s) => ({ value: String(s), label: scaleLabel(s) })), "1", (v) => setScale(Number(v) as Scale));
  const paintDisplay = (): void => {
    summaries.get("display")?.replaceChildren(`${THEME_LABEL[currentTheme()]} · ${scaleLabel(currentScale())}`);
  };
  onTheme((t) => {
    theme.set(t);
    paintDisplay();
  });
  onScale((s) => {
    scale.set(String(s));
    paintDisplay();
  });

  const pages: Record<Page, HTMLElement> = {
    network: h("div", { class: "set-rows" },
      settingRow("Nom", null, ssid),
      settingRow("Mot de passe", null, pass, eye),
      applyRow,
      sourceRow),
    protection: h("div", { class: "set-rows" },
      settingRow("Bloqueur de publicités", "Sur tous les appareils connectés", setting("adBlock", "Bloqueur de publicités")),
      settingRow("Isoler les appareils", "Aucun accès à ce PC ni au réseau local", setting("isolate", "Isoler les appareils")),
      settingRow("Débit maximal", "Par appareil, sauf réglage individuel", limit.el)),
    advanced: h("div", { class: "set-rows" },
      settingRow("Serveur DNS", "Pour les appareils connectés", dns.el),
      customRow,
      settingRow("Toujours allumé", "Même sans appareil connecté", setting("keepAlive", "Toujours allumé")),
      settingRow("Relance automatique", "Après une coupure du Wi-Fi", setting("autoRestart", "Relance automatique"))),
    app: h("div", { class: "set-rows" },
      settingRow("Démarrer avec Windows", null, setting("autostart", "Démarrer avec Windows")),
      settingRow("Partager au lancement", null, setting("shareOnLaunch", "Partager au lancement")),
      settingRow("Notifications", "Quand un appareil se connecte", setting("notifications", "Notifications"))),
    display: h("div", { class: "set-rows" },
      settingRow("Thème", "Système : suit le réglage de Windows", theme.el),
      settingRow("Taille de l'interface", "Aussi avec Ctrl + et Ctrl −", scale.el)),
  };

  // ---------- Accueil des réglages : une ligne par page, avec un résumé ----------
  const quit = h("button", { class: "btn btn-danger btn-block", type: "button" }, icon("logout", 16), "Quitter axios");
  quit.addEventListener("click", () => api.quit());
  const home = h("div", { class: "set-home" },
    h("div", { class: "set-rows" }, ...PAGES.map((p) => {
      const summary = h("span", { class: "nav-sum" });
      summaries.set(p.id, summary);
      const row = h("button", { class: "nav-row", type: "button" },
        h("span", { class: "nav-icon", "data-tone": p.id }, icon(p.icon, 16)),
        h("span", { class: "nav-text" }, h("span", { class: "nav-title" }, p.title), summary),
        h("span", { class: "nav-chevron" }, icon("chevron", 16)));
      row.addEventListener("click", () => open(p.id, true));
      return row;
    })),
    h("div", { class: "set-quit" }, quit));

  paintDisplay();

  const el = h("div", { class: "view settings" }, home);
  let page: Page | null = null;

  /**
   * Affiche une page. `slide` : on avance (la page arrive de droite) ou on revient (de gauche) ;
   * transition courte, seulement entre la liste et ses pages.
   */
  function open(p: Page | null, slide = false): void {
    const forward = p !== null;
    page = p;
    const next = p ? pages[p] : home;
    el.replaceChildren(next);
    header.setTitle(p ? PAGES.find((x) => x.id === p)?.title ?? "Réglages" : "Réglages");
    el.parentElement?.scrollTo({ top: 0 });
    if (!slide) return;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    next.animate(
      [{ opacity: 0, transform: still ? "none" : `translateX(${forward ? 10 : -10}px)` }, { opacity: 1, transform: "none" }],
      { duration: 180, easing: "cubic-bezier(0.23, 1, 0.32, 1)" },
    );
  }

  store.subscribe((st) => {
    const s = st.snapshot;
    const set = st.settings;
    if (s) {
      if (applyRow.hidden && document.activeElement !== ssid) ssid.value = s.ssid;
      if (applyRow.hidden && document.activeElement !== pass) pass.value = s.passphrase;
      sourceRow.hidden = st.sources.length === 0;
      source.setOptions(st.sources.map((x) => ({ value: x.id, label: x.name })));
      source.set(s.source?.id ?? "");
      summaries.get("network")?.replaceChildren(s.source ? `${s.ssid} · ${s.source.name}` : s.ssid);
    }
    if (set) {
      for (const [key, t] of toggles) t.set(Boolean(set[key]));
      limit.set(String(set.defaultLimit));
      dns.set(set.dns);
      customRow.hidden = set.dns !== "custom";
      if (document.activeElement !== customDns) customDns.value = set.customDns;
      const protection = [
        set.adBlock ? "Bloqueur de pubs" : null,
        set.isolate ? "Isolation" : null,
        set.defaultLimit !== null ? `≤ ${limitLabel(set.defaultLimit)}` : null,
      ].filter(Boolean).join(" · ");
      summaries.get("protection")?.replaceChildren(protection || "Aucune");
      summaries.get("advanced")?.replaceChildren(
        `DNS ${DNS.find((d) => d.value === set.dns)?.label.toLowerCase() ?? ""}${set.keepAlive ? " · toujours allumé" : ""}`);
      summaries.get("app")?.replaceChildren(set.autostart ? "Démarre avec Windows" : "Démarrage manuel");
    }
  });

  // Page forçable par l'URL au premier affichage (`?page=protection`), pour les captures.
  let asked = PAGES.find((p) => p.id === new URLSearchParams(location.search).get("page"))?.id ?? null;

  return {
    el,
    shown: () => {
      open(asked);
      asked = null;
    },
    back: () => {
      if (page === null) return false;
      open(null, true);
      return true;
    },
  };
}
