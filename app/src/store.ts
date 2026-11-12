import type { Settings, Snapshot, Source, Stats, View } from "./types";

export interface Store<T> {
  get(): Readonly<T>;
  set(patch: Partial<T>): void;
  /** Appelle `fn` tout de suite puis à chaque changement ; renvoie le désabonnement. */
  subscribe(fn: (s: Readonly<T>) => void): () => void;
}

export function createStore<T extends object>(initial: T): Store<T> {
  let state = initial;
  const listeners = new Set<(s: Readonly<T>) => void>();
  return {
    get: () => state,
    set(patch) {
      state = { ...state, ...patch };
      listeners.forEach((fn) => fn(state));
    },
    subscribe(fn) {
      listeners.add(fn);
      fn(state);
      return () => listeners.delete(fn);
    },
  };
}

/** Secondes d'historique conservées pour la courbe en direct. */
export const LIVE_POINTS = 60;

export interface AppState {
  view: View;
  snapshot: Snapshot | null;
  stats: Stats;
  settings: Settings | null;
  sources: Source[];
  /** Transition demandée localement, affichée immédiatement. */
  pending: "starting" | "stopping" | null;
  live: { down: number[]; up: number[] };
}

export const emptyStats = (): Stats => ({
  rateDown: 0,
  rateUp: 0,
  totalDown: 0,
  totalUp: 0,
  adsBlocked: 0,
  devices: [],
});

export function initialState(view: AppState["view"]): AppState {
  return {
    view,
    snapshot: null,
    stats: emptyStats(),
    settings: null,
    sources: [],
    pending: null,
    live: { down: new Array<number>(LIVE_POINTS).fill(0), up: new Array<number>(LIVE_POINTS).fill(0) },
  };
}

/** Ajoute un échantillon à l'historique glissant. */
export function pushLive(live: AppState["live"], down: number, up: number): AppState["live"] {
  return { down: [...live.down.slice(1), down], up: [...live.up.slice(1), up] };
}
