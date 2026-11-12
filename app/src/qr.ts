import QRCode from "qrcode";
import { h } from "./dom";
import { wifiPayload } from "./format";
import { icon } from "./icons";

export interface QrDialog {
  el: HTMLElement;
  open(ssid: string, passphrase: string): void;
}

export function createQr(): QrDialog {
  const box = h("div", { class: "qr-box", role: "img" });
  const name = h("p", { class: "qr-name" });
  const closeBtn = h("button", { class: "icon-btn qr-close", type: "button", "aria-label": "Fermer" }, icon("close", 18));
  const panel = h("div", { class: "qr-panel", role: "dialog", "aria-modal": "true", "aria-label": "QR code du réseau" },
    closeBtn, box, name, h("p", { class: "qr-hint" }, "Scannez pour vous connecter"));
  const el = h("div", { class: "overlay", hidden: true }, panel);

  let back: Element | null = null;
  const close = (): void => {
    if (el.hidden) return;
    el.hidden = true;
    if (back instanceof HTMLElement) back.focus();
  };
  closeBtn.addEventListener("click", close);
  el.addEventListener("click", (e) => { if (e.target === el) close(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });

  return {
    el,
    open(ssid, passphrase) {
      back = document.activeElement;
      QRCode.toString(wifiPayload(ssid, passphrase), {
        type: "svg", margin: 0, errorCorrectionLevel: "M", color: { dark: "#14181f", light: "#ffffff" },
      }).then((svg) => {
        box.innerHTML = svg;
        box.setAttribute("aria-label", `QR code du réseau ${ssid}`);
        name.textContent = ssid;
        el.hidden = false;
        closeBtn.focus();
      }, () => undefined);
    },
  };
}
