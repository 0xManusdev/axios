import { h } from "../dom";
import { bytesText, rateText } from "../format";
import {
  deviceName, errText, KIND_ICON, LIMITS, limitLabel, since, type Ctx, type ViewHandle,
} from "../context";
import { icon } from "../icons";
import type { Device } from "../types";
import { iconButton, openMenu, rateLabel, tag } from "../ui";

interface Row {
  el: HTMLElement;
  kind: HTMLElement;
  name: HTMLElement;
  input: HTMLInputElement;
  tags: HTMLElement;
  sub: HTMLElement;
  ip: HTMLElement;
  down: HTMLElement;
  up: HTMLElement;
  total: HTMLElement;
  device: Device;
  editing: boolean;
}

export function createDevices(ctx: Ctx): ViewHandle {
  const { api, store } = ctx;
  const rows = new Map<string, Row>();
  const body = h("div", { class: "tbl-body", role: "rowgroup" });
  // En-tête : seulement en fenêtre large, quand les colonnes de détail apparaissent.
  const head = h("div", { class: "tbl-head", role: "row" },
    h("span", {}, "Appareil"), h("span", { class: "col-ip" }, "Adresse"), h("span", { class: "num" }, "Débit"),
    h("span", { class: "num col-total" }, "Total"), h("span", {}));
  const emptyHint = h("p", { class: "dim" });
  const empty = h("div", { class: "empty" }, h("p", {}, "Aucun appareil connecté"), emptyHint);

  async function act(row: Row, patch: Partial<Device>, run: () => Promise<void>, done?: string): Promise<void> {
    const before = row.device;
    row.device = { ...before, ...patch };
    paint(row);
    order();
    try {
      await run();
      if (done) ctx.notify(done);
    } catch (e) {
      row.device = before;
      paint(row);
      order();
      ctx.notify(errText(e), "error");
    }
  }

  function startRename(row: Row): void {
    row.editing = true;
    row.input.value = deviceName(row.device);
    row.name.hidden = true;
    row.input.hidden = false;
    row.input.focus();
    row.input.select();
  }
  function endRename(row: Row, save: boolean): void {
    if (!row.editing) return;
    row.editing = false;
    row.input.hidden = true;
    row.name.hidden = false;
    const alias = row.input.value.trim();
    if (save && alias !== deviceName(row.device)) {
      void act(row, { alias }, () => api.renameDevice(row.device.id, alias), "Appareil renommé");
    }
  }

  function menu(row: Row, anchor: HTMLElement): void {
    const d = row.device;
    openMenu(anchor, [
      { label: "Renommer", icon: "pencil", onPick: () => startRename(row) },
      {
        label: "Limiter le débit", icon: "gauge",
        onPick: () => openMenu(anchor, LIMITS.map((l) => ({
          label: limitLabel(l),
          checked: row.device.limit === l,
          onPick: () => void act(row, { limit: l }, () => api.setDeviceLimit(row.device.id, l)),
        }))),
      },
      {
        label: "Copier l'adresse MAC", icon: "copy", disabled: !d.mac,
        onPick: () => void navigator.clipboard.writeText(d.mac ?? "").then(() => ctx.notify("Adresse copiée")),
      },
      "separator",
      d.blocked
        ? { label: "Rétablir internet", icon: "wifi", onPick: () => void act(row, { blocked: false }, () => api.setDeviceBlocked(d.id, false), "Internet rétabli") }
        : { label: "Couper internet", icon: "ban", danger: true, onPick: () => void act(row, { blocked: true }, () => api.setDeviceBlocked(d.id, true), "Internet coupé") },
    ]);
  }

  function create(d: Device): Row {
    const kind = h("span", { class: "dv-kind" });
    const name = h("span", { class: "dv-name" });
    const input = h("input", { class: "inline-input", type: "text", maxlength: 40, hidden: true, "aria-label": "Nom de l'appareil" });
    const tags = h("span", { class: "dv-tags" });
    const sub = h("span", { class: "dv-sub" });
    const ip = h("span", { class: "mono dim col-ip" });
    const down = h("span", {});
    const up = h("span", { class: "dim dv-up" });
    const total = h("span", { class: "num mono col-total" });
    const el = h("div", { class: "tbl-row", role: "row" });
    const row: Row = { el, kind, name, input, tags, sub, ip, down, up, total, device: d, editing: false };
    const more = iconButton("more", "Options", (b) => menu(row, b));
    name.addEventListener("dblclick", () => startRename(row));
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") endRename(row, true);
      if (e.key === "Escape") endRename(row, false);
    });
    input.addEventListener("blur", () => endRename(row, true));

    el.append(
      h("div", { class: "dv-id" }, kind,
        h("div", { class: "dv-text" }, h("div", { class: "dv-line" }, name, input, tags), sub)),
      ip,
      h("span", { class: "num mono dv-rate" }, down, up),
      total,
      more);
    return row;
  }

  function paint(row: Row): void {
    const d = row.device;
    row.el.classList.toggle("is-muted", d.blocked);
    row.kind.replaceChildren(icon(KIND_ICON[d.kind], 16));
    if (!row.editing) row.name.textContent = deviceName(d);
    row.tags.replaceChildren(
      ...(d.blocked ? [tag("coupé", "off")] : []),
      ...(d.limit !== null ? [tag(`≤ ${limitLabel(d.limit)}`)] : []),
    );
    row.sub.textContent = [d.alias ? d.hostname || d.vendor : d.vendor, since(d.connectedAt)].filter(Boolean).join(" · ");
    row.ip.textContent = d.ip ?? "—";
    row.down.replaceChildren(d.blocked ? "—" : rateLabel("down", rateText(d.rateDown)));
    row.up.replaceChildren(...(d.blocked ? [] : [rateLabel("up", rateText(d.rateUp))]));
    row.total.textContent = bytesText(d.totalDown + d.totalUp);
  }

  /** Appareils coupés en bas ; ne déplace rien si l'ordre est déjà bon (focus du renommage). */
  function order(): void {
    const els = [...rows.values()]
      .sort((a, b) => Number(a.device.blocked) - Number(b.device.blocked))
      .map((r) => r.el);
    const cur = Array.from(body.children);
    if (els.length !== cur.length || els.some((e, i) => e !== cur[i])) body.replaceChildren(...els);
    empty.hidden = els.length > 0;
    head.hidden = els.length === 0;
  }

  store.subscribe((st) => {
    emptyHint.textContent = st.snapshot?.status === "on"
      ? "Scannez le QR code pour rejoindre le réseau"
      : "Démarrez le partage pour connecter des appareils";
    const seen = new Set<string>();
    for (const d of st.stats.devices) {
      seen.add(d.id);
      const row = rows.get(d.id);
      if (row) row.device = d;
      else rows.set(d.id, create(d));
      paint(rows.get(d.id) as Row);
    }
    for (const id of [...rows.keys()]) if (!seen.has(id)) rows.delete(id);
    order();
  });

  return { el: h("div", { class: "view tbl", role: "table", "aria-label": "Appareils" }, head, body, empty) };
}
