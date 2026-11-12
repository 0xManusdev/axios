import type { Api } from "./api";
import type { IconName } from "./icons";
import type { AppState, Store } from "./store";
import type { Device, DeviceKind, SourceKind, View } from "./types";

/** Ce que chaque écran reçoit. */
export interface Ctx {
  api: Api;
  store: Store<AppState>;
  notify(message: string, kind?: "info" | "error"): void;
  openQr(): void;
  go(view: View): void;
}

export interface ViewHandle {
  el: HTMLElement;
  /** Appelé quand l'écran devient visible. */
  shown?(): void;
  /** Retour interne (sous-page) ; `false` si l'écran n'a rien à dépiler. */
  back?(): boolean;
}

export const KIND_ICON: Record<DeviceKind, IconName> = {
  phone: "phone",
  laptop: "laptop",
  tablet: "tablet",
  tv: "tv",
  other: "chip",
};

export const SOURCE_ICON: Record<SourceKind, IconName> = {
  wifi: "wifi",
  ethernet: "ethernet",
  cellular: "cellular",
};

export const deviceName = (d: Pick<Device, "alias" | "hostname" | "vendor">): string =>
  d.alias || d.hostname || (d.vendor ? `Appareil ${d.vendor}` : "Appareil inconnu");

/** Durée courte depuis `since` : « 9 min », « 2 h 12 ». */
export function since(since: number | null, now = Date.now()): string {
  if (since === null) return "";
  const min = Math.max(0, Math.floor((now - since) / 60_000));
  if (min < 1) return "à l'instant";
  if (min < 60) return `${min} min`;
  const hrs = Math.floor(min / 60);
  const rest = min % 60;
  return rest ? `${hrs} h ${String(rest).padStart(2, "0")}` : `${hrs} h`;
}

export const LIMITS: Array<number | null> = [null, 1, 2, 5, 10, 25];

export const limitLabel = (l: number | null): string =>
  l === null ? "Illimité" : `${l.toLocaleString("fr-FR")} Mb/s`;

export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return "Une erreur est survenue";
}
