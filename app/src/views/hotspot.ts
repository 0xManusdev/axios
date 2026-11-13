import QRCode from "qrcode";
import { h } from "../dom";
import { bandLabel, rateText, validateSsid, wifiPayload } from "../format";
import { errText, type Ctx } from "../context";
import { icon } from "../icons";
import type { Band, Snapshot, Status } from "../types";
import { confirmCopy, iconButton, rateLabel, select, toggle, type Option } from "../ui";

/**
 * Bandes proposées. La carte Wi-Fi n'a qu'une radio : le point d'accès doit rester sur la
 * bande du Wi-Fi amont, les autres sont grisées avec la raison.
 */
export function bandOptions(s: Snapshot): Option<Band>[] {
  const upstream = s.source?.kind === "wifi" ? s.source.band : null;
  return s.supportedBands.map((b) => {
    const clash = b !== "auto" && upstream !== null && b !== upstream;
    return {
      value: b,
      label: clash ? `${bandLabel(b)} · Wi-Fi en ${bandLabel(upstream ?? "auto")}` : bandLabel(b),
      disabled: clash,
    };
  });
}

const SIGNAL_LABEL: Record<Status, string> = {
  off: "Partage arrêté", starting: "Démarrage…", on: "Partage actif", stopping: "Arrêt…", error: "Partage en erreur",
};

/** Carte du point d'accès : le réseau, son QR code, une seule action principale. */
export function createHotspot(ctx: Ctx): HTMLElement {
  const { api, store } = ctx;
  const snap = (): Snapshot | null => store.get().snapshot;

  // --- Nom, avec le signal d'état (bleu = partage actif) ---
  const signal = h("span", { class: "hs-signal", role: "img" }, icon("wifi", 18));
  const name = h("button", { class: "hs-name", type: "button", title: "Renommer le réseau" });
  const nameInput = h("input", { class: "hs-name-input", type: "text", maxlength: 32, spellcheck: "false", hidden: true, "aria-label": "Nom du réseau" });
  const endRename = (): void => {
    nameInput.hidden = true;
    name.hidden = false;
    signal.hidden = false;
  };
  name.addEventListener("click", () => {
    nameInput.value = snap()?.ssid ?? "";
    name.hidden = true;
    signal.hidden = true;
    nameInput.hidden = false;
    nameInput.focus();
    nameInput.select();
  });
  async function commitName(): Promise<void> {
    const s = snap();
    const ssid = nameInput.value.trim();
    if (!s || ssid === s.ssid) return endRename();
    const invalid = validateSsid(ssid);
    if (invalid) return ctx.notify(invalid, "error");
    nameInput.disabled = true;
    try {
      await api.configureNetwork(ssid, s.passphrase, s.band);
      ctx.notify(s.status === "on" ? "Nom changé, le réseau redémarre" : "Nom changé");
      endRename();
    } catch (e) {
      ctx.notify(errText(e), "error");
    } finally {
      nameInput.disabled = false;
    }
  }
  nameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void commitName();
    if (e.key === "Escape") endRename();
  });
  nameInput.addEventListener("blur", () => { if (!nameInput.disabled && !nameInput.hidden) void commitName(); });

  // --- Mot de passe : un clic pour l'afficher, une icône pour copier ---
  let reveal = false;
  const pass = h("button", { class: "hs-pass mono", type: "button", title: "Afficher le mot de passe" });
  pass.addEventListener("click", () => {
    reveal = !reveal;
    pass.title = reveal ? "Masquer le mot de passe" : "Afficher le mot de passe";
    paintPass();
  });
  const copy = iconButton("copy", "Copier le mot de passe", (b) =>
    void navigator.clipboard.writeText(snap()?.passphrase ?? "").then(
      () => confirmCopy(b, "copy"),
      () => ctx.notify("Copie impossible", "error")));
  const paintPass = (): void => {
    const p = snap()?.passphrase ?? "";
    pass.textContent = reveal ? p : "•".repeat(Math.min(12, p.length));
  };

  // --- QR code, et la bande juste en dessous ---
  const qr = h("button", { class: "hs-qr", type: "button", "aria-label": "Agrandir le QR code", title: "Agrandir le QR code" });
  qr.addEventListener("click", () => ctx.openQr());
  let qrKey = "";
  function paintQr(s: Snapshot): void {
    const key = `${s.ssid}\n${s.passphrase}`;
    if (key === qrKey) return;
    qrKey = key;
    QRCode.toString(wifiPayload(s.ssid, s.passphrase), {
      type: "svg", margin: 0, errorCorrectionLevel: "M", color: { dark: "#171717", light: "#00000000" },
    }).then((svg) => { qr.innerHTML = svg; }, () => undefined);
  }
  const band = select<Band>("Bande Wi-Fi", [], "auto", async (b) => {
    const s = snap();
    if (!s) return;
    try {
      await api.configureNetwork(s.ssid, s.passphrase, b);
      ctx.notify(s.status === "on" ? "Bande changée, le réseau redémarre" : "Bande changée");
    } catch (e) {
      band.set(s.band);
      ctx.notify(errText(e), "error");
    }
  });

  // --- Débits, puis l'interrupteur du partage (même contrôle que dans les réglages) ---
  const rates = h("div", { class: "hs-rates mono" });
  const error = h("p", { class: "hs-error", hidden: true });
  const power = toggle("Partage", false, async (want) => {
    store.set({ pending: want ? "starting" : "stopping" });
    try {
      await api.setSharing(want);
    } catch (e) {
      ctx.notify(errText(e), "error");
    } finally {
      store.set({ pending: null });
    }
  });
  const powerLabel = h("span", { class: "hs-power-label" });

  store.subscribe((st) => {
    const s = st.snapshot;
    if (!s) return;
    const status = st.pending ?? s.status;
    const on = status === "on";
    const busy = status === "starting" || status === "stopping";
    signal.dataset.status = status;
    signal.setAttribute("aria-label", SIGNAL_LABEL[status]);
    signal.title = SIGNAL_LABEL[status];
    if (nameInput.hidden) name.textContent = s.ssid;
    paintPass();
    paintQr(s);
    qr.classList.toggle("is-idle", !on);
    band.setOptions(bandOptions(s));
    band.set(s.band);
    // La ligne reste en place (pas de saut de mise en page) : grisée, sans valeur, à l'arrêt.
    rates.classList.toggle("is-idle", !on);
    rates.replaceChildren(
      rateLabel("down", on ? rateText(st.stats.rateDown) : "—"),
      rateLabel("up", on ? rateText(st.stats.rateUp) : "—"));
    error.hidden = !s.error;
    error.textContent = s.error ?? "";
    // Pendant une transition, l'interrupteur montre l'état visé et reste inactif.
    power.set(on || status === "starting");
    power.disable(busy);
    powerLabel.textContent = SIGNAL_LABEL[status];
    powerLabel.dataset.status = status;
  });

  return h("section", { class: "hotspot", "aria-label": "Point d'accès" },
    h("div", { class: "hs-main" },
      h("div", { class: "hs-id" },
        h("div", { class: "hs-name-row" }, name, nameInput, signal),
        h("div", { class: "hs-pass-row" }, pass, copy),
        rates,
        h("label", { class: "hs-power" }, power.el, powerLabel)),
      h("div", { class: "hs-code" }, qr, h("div", { class: "hs-band" }, band.el))),
    error);
}
