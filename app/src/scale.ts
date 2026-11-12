import type { Api } from "./api";

/** Échelles proposées (1 = taille normale). */
export const SCALES = [0.8, 0.9, 1, 1.1] as const;
export type Scale = (typeof SCALES)[number];

const KEY = "axios.scale";
const listeners = new Set<(s: Scale) => void>();
let api: Api | null = null;
let current: Scale = 1;

const isScale = (n: number): n is Scale => (SCALES as readonly number[]).includes(n);

/** Préférence de ce poste ; le stockage peut être indisponible (fenêtre privée, etc.). */
function stored(): Scale {
  try {
    const n = Number(localStorage.getItem(KEY));
    return isScale(n) ? n : 1;
  } catch {
    return 1;
  }
}

export const scaleLabel = (s: Scale): string => `${Math.round(s * 100)} %`;
export const currentScale = (): Scale => current;

export function setScale(s: Scale): void {
  current = s;
  api?.setZoom(s);
  try {
    localStorage.setItem(KEY, String(s));
  } catch {
    // Préférence non mémorisée : sans conséquence.
  }
  listeners.forEach((fn) => fn(s));
}

export function onScale(fn: (s: Scale) => void): void {
  listeners.add(fn);
  fn(current);
}

/** Applique l'échelle mémorisée et branche Ctrl + / Ctrl − / Ctrl 0. */
export function initScale(a: Api): void {
  api = a;
  setScale(stored());
  document.addEventListener("keydown", (e) => {
    if (!e.ctrlKey || e.altKey) return;
    const i = SCALES.indexOf(current);
    let next: Scale | undefined;
    if (e.key === "-") next = SCALES[Math.max(0, i - 1)];
    else if (e.key === "=" || e.key === "+") next = SCALES[Math.min(SCALES.length - 1, i + 1)];
    else if (e.key === "0") next = 1;
    if (next === undefined) return;
    e.preventDefault();
    if (next !== current) setScale(next);
  });
}
