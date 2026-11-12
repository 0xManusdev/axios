/** Thème de l'interface : clair, sombre, ou celui de Windows. */
export const THEMES = ["light", "dark", "system"] as const;
export type Theme = (typeof THEMES)[number];

export const THEME_LABEL: Record<Theme, string> = { light: "Clair", dark: "Sombre", system: "Système" };

const KEY = "axios.theme";
const listeners = new Set<(t: Theme) => void>();
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");
let current: Theme = "system";

const isTheme = (v: string | null): v is Theme => (THEMES as readonly string[]).includes(v ?? "");

/** Préférence de ce poste ; le stockage peut être indisponible. */
function stored(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return isTheme(v) ? v : "system";
  } catch {
    return "system";
  }
}

/** Pose le thème effectif sur la racine (`data-theme`), lu par la feuille de style. */
function apply(): void {
  const dark = current === "dark" || (current === "system" && systemDark.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export const currentTheme = (): Theme => current;

export function setTheme(t: Theme): void {
  current = t;
  apply();
  try {
    localStorage.setItem(KEY, t);
  } catch {
    // Préférence non mémorisée : sans conséquence.
  }
  listeners.forEach((fn) => fn(t));
}

export function onTheme(fn: (t: Theme) => void): void {
  listeners.add(fn);
  fn(current);
}

/** Applique le thème mémorisé et suit les changements de Windows en mode « Système ». */
export function initTheme(): void {
  current = stored();
  apply();
  systemDark.addEventListener("change", apply);
}
