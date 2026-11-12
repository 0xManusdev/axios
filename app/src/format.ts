const fr = (n: number, digits: number): string =>
  n.toLocaleString("fr-FR", { minimumFractionDigits: digits, maximumFractionDigits: digits });

const UNITS = ["o", "Ko", "Mo", "Go", "To"];

export interface Human {
  value: string;
  unit: string;
}

/** Valeur lisible en octets (base 1000) : 1 décimale sous 10, sinon entier. */
export function humanBytes(bytes: number): Human {
  let v = Math.max(0, bytes);
  let i = 0;
  while (v >= 999.5 && i < UNITS.length - 1) {
    v /= 1000;
    i++;
  }
  const digits = i === 0 ? 0 : v < 10 ? 1 : 0;
  return { value: fr(v, digits), unit: UNITS[i] ?? "o" };
}

export function humanRate(bytesPerSec: number): Human {
  const { value, unit } = humanBytes(bytesPerSec);
  return { value, unit: `${unit}/s` };
}

export const rateText = (b: number): string => {
  const { value, unit } = humanRate(b);
  return `${value} ${unit}`;
};

export const bytesText = (b: number): string => {
  const { value, unit } = humanBytes(b);
  return `${value} ${unit}`;
};

export function bandLabel(band: string): string {
  return band === "auto" ? "Auto" : `${band.replace(".", ",")} GHz`;
}

/** Échappe \ ; , : " pour la charge utile WIFI: */
const escapeWifi = (s: string): string => s.replace(/[\\;,:"]/g, (c) => `\\${c}`);

export function wifiPayload(ssid: string, pass: string): string {
  return `WIFI:T:WPA;S:${escapeWifi(ssid)};P:${escapeWifi(pass)};;`;
}

export function errMsg(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return "Une erreur est survenue";
}

export function validateSsid(ssid: string): string | null {
  const n = new TextEncoder().encode(ssid).length;
  return n >= 1 && n <= 32 ? null : "1 à 32 octets";
}

export function validatePassphrase(pass: string): string | null {
  return /^[\x20-\x7E]{8,63}$/.test(pass) ? null : "8 à 63 caractères ASCII";
}
