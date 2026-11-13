import { h } from "./dom";
import { bytesText, rateText } from "./format";
import type { Bucket } from "./types";

const NS = "http://www.w3.org/2000/svg";
const W = 600;

function svg<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number> = {}): SVGElementTagNameMap[K] {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  return el;
}

/** Échelle « ronde » au-dessus de `max` (1, 2 ou 5 × 10^n). */
export function niceMax(max: number, floor: number): number {
  const m = Math.max(max, floor);
  const p = 10 ** Math.floor(Math.log10(m));
  const n = m / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

/** Courbe lissée sans dépassement (contrôles au milieu des segments). */
function smoothPath(xs: number[], ys: number[]): string {
  let d = `M${xs[0] ?? 0},${ys[0] ?? 0}`;
  for (let i = 1; i < xs.length; i++) {
    const x0 = xs[i - 1] ?? 0;
    const x1 = xs[i] ?? 0;
    const y0 = ys[i - 1] ?? 0;
    const y1 = ys[i] ?? 0;
    const cx = (x0 + x1) / 2;
    d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`;
  }
  return d;
}

// ---------- Courbe en direct ----------

export interface LiveChart {
  el: HTMLElement;
  render(down: number[], up: number[]): void;
}

/** Courbe en direct ; sa hauteur suit son conteneur (repère interne fixe, étiré sans déformer les traits). */
export function liveChart(): LiveChart {
  const H = 160;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "chart-svg" });
  const defs = svg("defs");
  const grad = svg("linearGradient", { id: `fill-${Math.random().toString(36).slice(2)}`, x1: 0, y1: 0, x2: 0, y2: 1 });
  grad.append(
    svg("stop", { offset: "0%", style: "stop-color: var(--blue); stop-opacity: 0.18" }),
    svg("stop", { offset: "100%", style: "stop-color: var(--blue); stop-opacity: 0" }),
  );
  defs.append(grad);
  const grid = svg("g", { class: "chart-grid" });
  for (const f of [0.25, 0.5, 0.75]) {
    grid.append(svg("line", { x1: 0, x2: W, y1: H * f, y2: H * f, "vector-effect": "non-scaling-stroke" }));
  }
  const area = svg("path", { fill: `url(#${grad.id})` });
  const downLine = svg("path", { class: "chart-down", "vector-effect": "non-scaling-stroke" });
  const upLine = svg("path", { class: "chart-up", "vector-effect": "non-scaling-stroke" });
  root.append(defs, grid, area, upLine, downLine);
  const scale = h("span", { class: "chart-scale" });
  const el = h("div", { class: "chart" }, root, scale);

  return {
    el,
    render(down, up) {
      const max = niceMax(Math.max(...down, ...up), 125_000);
      const n = down.length;
      const xs = down.map((_, i) => (i / Math.max(1, n - 1)) * W);
      const y = (v: number): number => H - 2 - (v / max) * (H - 8);
      const dPath = smoothPath(xs, down.map(y));
      downLine.setAttribute("d", dPath);
      area.setAttribute("d", `${dPath} L${W},${H} L0,${H} Z`);
      upLine.setAttribute("d", smoothPath(xs, up.map(y)));
      scale.textContent = rateText(max);
    },
  };
}

// ---------- Histogramme ----------

export interface BarChart {
  el: HTMLElement;
  render(buckets: Bucket[], label: (b: Bucket, i: number) => string, tip: (b: Bucket) => string): void;
}

/** Histogramme ; sa hauteur suit son conteneur. */
export function barChart(): BarChart {
  const bars = h("div", { class: "bars" });
  const axis = h("div", { class: "bars-axis" });
  const scale = h("span", { class: "chart-scale" });
  const el = h("div", { class: "barchart" }, h("div", { class: "bars-wrap" }, bars, scale), axis);
  return {
    el,
    render(buckets, label, tip) {
      const max = niceMax(Math.max(...buckets.map((b) => b.down + b.up)), 1_000_000);
      bars.replaceChildren(...buckets.map((b) => {
        const total = b.down + b.up;
        // Empilés de bas en haut (column-reverse) : réception, puis envoi par-dessus.
        const col = h("div", { class: "bar", title: tip(b) },
          h("span", { class: "bar-down", style: `height:${(b.down / max) * 100}%` }),
          h("span", { class: "bar-up", style: `height:${(b.up / max) * 100}%` }),
        );
        if (total === 0) col.classList.add("is-empty");
        return col;
      }));
      axis.replaceChildren(...buckets.map((b, i) => h("span", {}, label(b, i))));
      scale.textContent = bytesText(max);
    },
  };
}
