import { h } from "../dom";
import { bytesText } from "../format";
import { barChart, liveChart } from "../charts";
import { deviceName, errText, KIND_ICON, type Ctx, type ViewHandle } from "../context";
import { icon } from "../icons";
import type { Bucket, DeviceKind, Range } from "../types";
import { segmented } from "../ui";

type Period = "live" | Range;

/** Appareils listés nommément sous le graphique (les suivants sont regroupés). */
const SHARE_ROWS = 3;

const PERIODS: Array<{ value: Period; label: string }> = [
  { value: "live", label: "Direct" },
  { value: "24h", label: "24 h" },
  { value: "7d", label: "7 jours" },
  { value: "30d", label: "30 jours" },
];

const WEEKDAY = new Intl.DateTimeFormat("fr-FR", { weekday: "short" });
const DAYDATE = new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short" });

function axisLabel(range: Range): (b: Bucket, i: number) => string {
  return (b, i) => {
    const d = new Date(b.t);
    if (range === "24h") return i % 6 === 0 ? `${d.getHours()} h` : "";
    if (range === "7d") return WEEKDAY.format(d).replace(".", "");
    return i % 5 === 0 ? String(d.getDate()) : "";
  };
}

function tipLabel(range: Range): (b: Bucket) => string {
  return (b) => {
    const d = new Date(b.t);
    const when = range === "24h" ? `${d.getHours()} h` : DAYDATE.format(d);
    return `${when} — ${bytesText(b.down + b.up)}`;
  };
}

export function createActivity(ctx: Ctx): ViewHandle {
  const { api, store } = ctx;
  // Période initiale forçable par l'URL (`?period=7d`), pour les captures de la maquette.
  const asked = new URLSearchParams(location.search).get("period");
  let period: Period = PERIODS.find((p) => p.value === asked)?.value ?? "live";
  let token = 0;

  const sub = h("span", { class: "act-sum mono" });
  const live = liveChart();
  const bars = barChart();
  const chart = { body: h("div", { class: "act-chart" }) };
  const shares = { body: h("div", { class: "act-shares" }) };

  const tabs = segmented<Period>("Période", PERIODS, period, (p) => {
    period = p;
    void refresh();
  });

  /** Derniers totaux affichés : le sous-titre suit aussi le compteur de pubs. */
  let totals: [number, number] = [0, 0];
  function summary(down: number, up: number): void {
    totals = [down, up];
    const parts = [`Reçu ${bytesText(down)}`, `Envoyé ${bytesText(up)}`];
    const st = store.get();
    if (st.settings?.adBlock) parts.push(`${st.stats.adsBlocked.toLocaleString("fr-FR")} pubs bloquées`);
    // Insécables à l'intérieur de chaque total : on ne passe à la ligne qu'entre deux totaux.
    sub.textContent = parts.map((p) => p.replace(/ /g, " ")).join("  ·  ");
  }

  /** Trois premiers appareils, puis les autres regroupés : la vue tient sans défilement. */
  function renderShares(all: Array<{ name: string; kind: DeviceKind; total: number }>): void {
    // Un seul appareil de plus : on l'affiche plutôt que « 1 autre ».
    const items = all.slice(0, all.length > SHARE_ROWS + 1 ? SHARE_ROWS : SHARE_ROWS + 1);
    const rest = all.slice(items.length);
    if (rest.length) {
      items.push({ name: `${rest.length} autre${rest.length > 1 ? "s" : ""}`, kind: "other", total: rest.reduce((a, r) => a + r.total, 0) });
    }
    const max = Math.max(1, ...items.map((i) => i.total));
    shares.body.replaceChildren(...(items.length ? items.map((i) =>
      h("div", { class: "share", "data-kind": i.kind },
        h("span", { class: "dv-kind", "data-kind": i.kind }, icon(KIND_ICON[i.kind], 14)),
        h("span", { class: "share-name" }, i.name),
        h("span", { class: "share-track" }, h("span", { class: "share-fill", style: `transform:scaleX(${i.total / max})` })),
        h("span", { class: "share-value" }, bytesText(i.total)),
      )) : [h("p", { class: "muted pad" }, "Aucune donnée")]));
  }

  function paintLive(): void {
    const st = store.get();
    live.render(st.live.down, st.live.up);
    summary(st.stats.totalDown, st.stats.totalUp);
    renderShares(st.stats.devices
      .map((d) => ({ name: deviceName(d), kind: d.kind, total: d.totalDown + d.totalUp }))
      .sort((a, b) => b.total - a.total));
  }

  async function refresh(): Promise<void> {
    const mine = ++token;
    if (period === "live") {
      chart.body.replaceChildren(live.el);
      paintLive();
      return;
    }
    chart.body.replaceChildren(bars.el);
    try {
      const usage = await api.getUsage(period);
      if (mine !== token) return;
      bars.render(usage.buckets, axisLabel(period), tipLabel(period));
      summary(usage.buckets.reduce((a, b) => a + b.down, 0), usage.buckets.reduce((a, b) => a + b.up, 0));
      renderShares(usage.devices.map((d) => ({ name: d.name, kind: d.kind, total: d.down + d.up })));
    } catch (e) {
      ctx.notify(errText(e), "error");
    }
  }

  store.subscribe(() => {
    if (period === "live") paintLive();
    else summary(...totals);
  });

  const el = h("div", { class: "view act" },
    h("div", { class: "toolbar" }, tabs.el, sub),
    chart.body,
    h("h2", { class: "section-title" }, "Par appareil"),
    shares.body);
  return { el, shown: () => void refresh() };
}
