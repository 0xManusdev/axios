// Contrat de données de l'interface v2 (celui que la coquille Rust devra fournir).

export type Status = "off" | "starting" | "on" | "stopping" | "error";
export type Band = "auto" | "2.4" | "5" | "6";
export type SourceKind = "wifi" | "ethernet" | "cellular";
export type DeviceKind = "phone" | "laptop" | "tablet" | "tv" | "other";
export type Range = "24h" | "7d" | "30d";
export type Dns = "auto" | "cloudflare" | "google" | "custom";
export type View = "devices" | "activity" | "settings";

/** Connexion internet partagée. */
export interface Source {
  id: string;
  name: string;
  kind: SourceKind;
  /** Bande du Wi-Fi amont : le point d'accès doit utiliser la même (une seule radio). */
  band: Band | null;
}

export interface Snapshot {
  status: Status;
  ssid: string;
  passphrase: string;
  band: Band;
  supportedBands: Band[];
  maxClients: number;
  source: Source | null;
  /** Horodatage (ms) du démarrage du partage, `null` s'il est arrêté. */
  startedAt: number | null;
  error: string | null;
}

export interface Device {
  id: string;
  /** Nom choisi par l'utilisateur ("" si aucun). */
  alias: string;
  hostname: string;
  vendor: string;
  kind: DeviceKind;
  ip: string | null;
  mac: string | null;
  /** Horodatage (ms) de connexion. */
  connectedAt: number | null;
  rateDown: number;
  rateUp: number;
  totalDown: number;
  totalUp: number;
  blocked: boolean;
  /** Débit maximal en Mb/s, `null` = illimité. */
  limit: number | null;
}

export interface Stats {
  rateDown: number;
  rateUp: number;
  totalDown: number;
  totalUp: number;
  adsBlocked: number;
  devices: Device[];
}

export interface Bucket {
  /** Début de la période (ms). */
  t: number;
  down: number;
  up: number;
}

export interface Usage {
  buckets: Bucket[];
  devices: Array<{ id: string; name: string; kind: DeviceKind; down: number; up: number }>;
}

export interface Settings {
  autostart: boolean;
  shareOnLaunch: boolean;
  notifications: boolean;
  adBlock: boolean;
  isolate: boolean;
  /** Débit maximal par défaut d'un nouvel appareil (Mb/s), `null` = illimité. */
  defaultLimit: number | null;
  dns: Dns;
  customDns: string;
  keepAlive: boolean;
  autoRestart: boolean;
}
