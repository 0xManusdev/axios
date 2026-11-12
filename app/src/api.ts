import type { Band, Range, Settings, Snapshot, Source, Stats, Usage } from "./types";

/** Commandes et événements attendus de la coquille Rust. */
export interface Api {
  getSnapshot(): Promise<Snapshot>;
  setSharing(on: boolean): Promise<Snapshot>;
  configureNetwork(ssid: string, passphrase: string, band: Band): Promise<Snapshot>;
  getSources(): Promise<Source[]>;
  setSource(id: string): Promise<Snapshot>;
  getSettings(): Promise<Settings>;
  updateSettings(patch: Partial<Settings>): Promise<Settings>;
  renameDevice(id: string, alias: string): Promise<void>;
  setDeviceBlocked(id: string, blocked: boolean): Promise<void>;
  setDeviceLimit(id: string, limit: number | null): Promise<void>;
  getUsage(range: Range): Promise<Usage>;
  onSnapshot(cb: (s: Snapshot) => void): () => void;
  onStats(cb: (s: Stats) => void): () => void;
  /** Échelle de l'interface (1 = normale). */
  setZoom(scale: number): void;
  minimize(): void;
  hide(): void;
  quit(): void;
}
