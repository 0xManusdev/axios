import type { Api } from "./api";
import type {
  Band, Bucket, Device, Range, Settings, Snapshot, Source, Stats, Status, Usage,
} from "./types";

/**
 * Données simulées, pour concevoir l'interface hors de Tauri.
 * URL : `mock=on|off|error`, `devices=0..4`.
 */

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

interface Sim extends Device {
  baseDown: number;
  baseUp: number;
}

function sims(now: number): Sim[] {
  const base = {
    rateDown: 0, rateUp: 0, blocked: false, limit: null as number | null,
  };
  return [
    {
      ...base, id: "A4:CF:99:12:0B:7E", alias: "iPhone de Camille", hostname: "iPhone", vendor: "Apple",
      kind: "phone", ip: "192.168.137.12", mac: "A4:CF:99:12:0B:7E", connectedAt: now - 47 * MINUTE,
      totalDown: 812_000_000, totalUp: 41_000_000, baseDown: 1_450_000, baseUp: 90_000,
    },
    {
      ...base, id: "3C:22:FB:88:21:F0", alias: "", hostname: "MacBook-Air", vendor: "Apple",
      kind: "laptop", ip: "192.168.137.31", mac: "3C:22:FB:88:21:F0", connectedAt: now - 2 * HOUR - 12 * MINUTE,
      totalDown: 1_930_000_000, totalUp: 212_000_000, baseDown: 2_900_000, baseUp: 310_000,
    },
    {
      ...base, id: "F0:18:98:4D:C3:15", alias: "", hostname: "Galaxy-S23", vendor: "Samsung",
      kind: "phone", ip: "192.168.137.47", mac: "F0:18:98:4D:C3:15", connectedAt: now - 9 * MINUTE,
      totalDown: 96_000_000, totalUp: 8_400_000, baseDown: 600_000, baseUp: 40_000, limit: 5,
    },
    {
      ...base, id: "8C:79:F5:02:9A:44", alias: "TV du salon", hostname: "", vendor: "Samsung",
      kind: "tv", ip: "192.168.137.53", mac: "8C:79:F5:02:9A:44", connectedAt: now - 5 * HOUR,
      totalDown: 3_100_000_000, totalUp: 23_000_000, baseDown: 3_800_000, baseUp: 30_000, blocked: true,
    },
  ];
}

const SOURCES: Source[] = [
  { id: "wifi", name: "Box-Maison", kind: "wifi", band: "2.4" },
  { id: "eth", name: "Ethernet", kind: "ethernet", band: null },
  { id: "cell", name: "Clé 4G Orange", kind: "cellular", band: null },
];

/** Profil d'usage d'une journée (0..1) selon l'heure. */
const dayProfile = (h: number): number =>
  0.15 + 0.35 * Math.exp(-((h - 13) ** 2) / 8) + 0.9 * Math.exp(-((h - 21) ** 2) / 6);

/** Pseudo-aléatoire déterministe : la maquette reste stable d'un rendu à l'autre. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function usage(range: Range, devices: Sim[], now: number): Usage {
  const rand = rng(range.length * 97);
  const n = range === "24h" ? 24 : range === "7d" ? 7 : 30;
  const step = range === "24h" ? HOUR : DAY;
  const end = range === "24h" ? Math.floor(now / HOUR) * HOUR : Math.floor(now / DAY) * DAY;
  const buckets: Bucket[] = [];
  for (let i = n - 1; i >= 0; i--) {
    const t = end - i * step;
    const scale = range === "24h"
      ? 420_000_000 * dayProfile(new Date(t).getHours())
      : 2_600_000_000 * (0.6 + rand() * 0.8) * (new Date(t).getDay() % 6 === 0 ? 1.35 : 1);
    const down = scale * (0.8 + rand() * 0.4);
    buckets.push({ t, down, up: down * (0.06 + rand() * 0.05) });
  }
  const totalDown = buckets.reduce((a, b) => a + b.down, 0);
  const totalUp = buckets.reduce((a, b) => a + b.up, 0);
  const weights = devices.map((d) => d.baseDown);
  const sum = weights.reduce((a, b) => a + b, 0) || 1;
  return {
    buckets,
    devices: devices
      .map((d, i) => ({
        id: d.id,
        name: d.alias || d.hostname || `Appareil ${d.vendor}`,
        kind: d.kind,
        down: (totalDown * (weights[i] ?? 0)) / sum,
        up: (totalUp * (weights[i] ?? 0)) / sum,
      }))
      .sort((a, b) => b.down - a.down),
  };
}

export function createMockApi(params: URLSearchParams): Api {
  const mode = params.get("mock") ?? "on";
  const initial: Status = mode === "on" ? "on" : mode === "error" ? "error" : "off";
  const now = Date.now();
  const all = sims(now).slice(0, Math.max(0, Math.min(4, Number(params.get("devices") ?? 4))));

  let snapshot: Snapshot = {
    status: initial,
    ssid: "axios",
    passphrase: "tulipe-2026",
    band: "auto",
    supportedBands: ["auto", "2.4", "5"],
    maxClients: 8,
    source: SOURCES[0] ?? null,
    startedAt: initial === "on" ? now - 47 * MINUTE : null,
    error: initial === "error" ? "Le point d'accès n'a pas pu démarrer" : null,
  };
  let settings: Settings = {
    autostart: true,
    shareOnLaunch: true,
    notifications: true,
    adBlock: true,
    isolate: false,
    defaultLimit: null,
    dns: "auto",
    customDns: "",
    keepAlive: true,
    autoRestart: true,
  };
  let adsBlocked = 1284;
  const snapListeners = new Set<(s: Snapshot) => void>();
  const statListeners = new Set<(s: Stats) => void>();
  const publish = (): void => snapListeners.forEach((cb) => cb(snapshot));
  const find = (id: string): Sim => {
    const d = all.find((x) => x.id === id);
    if (!d) throw new Error("Appareil introuvable");
    return d;
  };

  let t = 0;
  setInterval(() => {
    t += 1;
    const on = snapshot.status === "on";
    for (const [i, d] of all.entries()) {
      const wave = 0.55 + 0.45 * Math.sin(t / 6 + i * 1.7) + Math.random() * 0.25;
      const cap = d.limit === null ? Infinity : (d.limit * 1_000_000) / 8;
      d.rateDown = on && !d.blocked ? Math.min(cap, d.baseDown * wave) : 0;
      d.rateUp = on && !d.blocked ? Math.min(cap, d.baseUp * wave) : 0;
      d.totalDown += d.rateDown;
      d.totalUp += d.rateUp;
    }
    if (on && settings.adBlock && Math.random() < 0.3) adsBlocked += 1;
    const devices: Device[] = on ? all.map(({ baseDown: _d, baseUp: _u, ...dev }) => ({ ...dev })) : [];
    const stats: Stats = {
      rateDown: devices.reduce((a, d) => a + d.rateDown, 0),
      rateUp: devices.reduce((a, d) => a + d.rateUp, 0),
      totalDown: all.reduce((a, d) => a + d.totalDown, 0),
      totalUp: all.reduce((a, d) => a + d.totalUp, 0),
      adsBlocked,
      devices,
    };
    statListeners.forEach((cb) => cb(stats));
  }, 1000);

  const setStatus = (status: Status, error: string | null = null): void => {
    const startedAt = status === "on" ? snapshot.startedAt ?? Date.now() : status === "off" ? null : snapshot.startedAt;
    snapshot = { ...snapshot, status, error, startedAt };
    publish();
  };

  return {
    getSnapshot: async () => snapshot,
    async setSharing(on) {
      setStatus(on ? "starting" : "stopping");
      await delay(on ? 1400 : 700);
      setStatus(on ? "on" : "off");
      return snapshot;
    },
    async configureNetwork(ssid, passphrase, band: Band) {
      await delay(500);
      const src = snapshot.source;
      if (band !== "auto" && src?.kind === "wifi" && src.band && src.band !== band) {
        throw new Error("Bande incompatible avec votre connexion");
      }
      snapshot = { ...snapshot, ssid, passphrase, band };
      publish();
      return snapshot;
    },
    getSources: async () => SOURCES,
    async setSource(id) {
      await delay(400);
      const source = SOURCES.find((s) => s.id === id) ?? null;
      snapshot = { ...snapshot, source, band: "auto" };
      publish();
      return snapshot;
    },
    getSettings: async () => settings,
    async updateSettings(patch) {
      await delay(120);
      settings = { ...settings, ...patch };
      return settings;
    },
    async renameDevice(id, alias) {
      find(id).alias = alias.trim();
    },
    async setDeviceBlocked(id, blocked) {
      find(id).blocked = blocked;
    },
    async setDeviceLimit(id, limit) {
      find(id).limit = limit;
    },
    getUsage: async (range) => usage(range, all, Date.now()),
    onSnapshot(cb) {
      snapListeners.add(cb);
      return () => snapListeners.delete(cb);
    },
    onStats(cb) {
      statListeners.add(cb);
      return () => statListeners.delete(cb);
    },
    // Navigateur : approximation par la propriété CSS `zoom`.
    setZoom: (scale) => { document.documentElement.style.setProperty("zoom", String(scale)); },
    minimize: () => undefined,
    hide: () => undefined,
    quit: () => undefined,
  };
}

/** Historique initial plausible pour la courbe en direct. */
export function seedLive(n: number): { down: number[]; up: number[] } {
  const down: number[] = [];
  const up: number[] = [];
  for (let i = 0; i < n; i++) {
    const x = i / 7;
    down.push(Math.max(0, 4_200_000 + Math.sin(x) * 1_600_000 + Math.sin(x * 2.7) * 700_000));
    up.push(Math.max(0, 380_000 + Math.sin(x * 1.3 + 1) * 160_000));
  }
  return { down, up };
}

