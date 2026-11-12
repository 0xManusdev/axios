import { h } from "./dom";
import { icon, type IconName } from "./icons";

// ---------- Interrupteur ----------

export interface Toggle {
  el: HTMLButtonElement;
  set(on: boolean): void;
  disable(disabled: boolean): void;
}

export function toggle(label: string, on: boolean, onChange: (on: boolean) => void): Toggle {
  const el = h("button", { class: "switch", role: "switch", "aria-label": label, type: "button" },
    h("span", { class: "switch-knob" }));
  let value = on;
  const set = (v: boolean): void => {
    value = v;
    el.setAttribute("aria-checked", String(v));
  };
  set(on);
  el.addEventListener("click", () => {
    set(!value);
    onChange(value);
  });
  return { el, set, disable: (d) => { el.disabled = d; } };
}

// ---------- Sélecteur segmenté ----------

export interface Option<T extends string> {
  value: T;
  label: string;
  disabled?: boolean;
  title?: string;
}

export interface Segmented<T extends string> {
  el: HTMLElement;
  set(value: T): void;
  setOptions(options: Option<T>[]): void;
}

export function segmented<T extends string>(
  label: string,
  options: Option<T>[],
  value: T,
  onChange: (v: T) => void,
): Segmented<T> {
  const el = h("div", { class: "seg", role: "radiogroup", "aria-label": label });
  let current = value;
  let opts = options;
  const render = (): void => {
    el.replaceChildren(...opts.map((o) => {
      const b = h("button", {
        class: "seg-btn", type: "button", role: "radio",
        "aria-checked": String(o.value === current), disabled: o.disabled, title: o.title,
      }, o.label);
      b.addEventListener("click", () => {
        if (o.value === current) return;
        current = o.value;
        render();
        onChange(o.value);
      });
      return b;
    }));
  };
  render();
  // Rendu seulement si quelque chose change : le store notifie chaque seconde.
  return {
    el,
    set: (v) => {
      if (v === current) return;
      current = v;
      render();
    },
    setOptions: (o) => {
      if (JSON.stringify(o) === JSON.stringify(opts)) return;
      opts = o;
      render();
    },
  };
}

// ---------- Menu contextuel ----------

export interface MenuItem {
  label: string;
  icon?: IconName;
  checked?: boolean;
  danger?: boolean;
  disabled?: boolean;
  onPick: () => void;
}

export type MenuEntry = MenuItem | "separator";

let closeOpenMenu: (() => void) | null = null;
let openAnchor: HTMLElement | null = null;

/**
 * Ouvre un menu sous `anchor`, dans la fenêtre `host`. Recliquer sur le même bouton le referme
 * (un clic déroule, le suivant replie).
 */
export function openMenu(anchor: HTMLElement, entries: MenuEntry[], align: "start" | "end" = "end"): void {
  const toggling = openAnchor === anchor;
  closeOpenMenu?.();
  if (toggling) return;
  openAnchor = anchor;
  const host = anchor.closest<HTMLElement>(".window") ?? document.body;
  const menu = h("div", { class: "menu", role: "menu" });
  for (const entry of entries) {
    if (entry === "separator") {
      menu.append(h("div", { class: "menu-sep", role: "separator" }));
      continue;
    }
    const item = h("button", {
      class: `menu-item${entry.danger ? " is-danger" : ""}`, type: "button",
      role: entry.checked === undefined ? "menuitem" : "menuitemradio",
      "aria-checked": entry.checked === undefined ? undefined : String(entry.checked),
      disabled: entry.disabled,
    },
      h("span", { class: "menu-icon" }, entry.icon ? icon(entry.icon, 16) : entry.checked ? icon("check", 16) : ""),
      h("span", { class: "menu-label" }, entry.label),
    );
    item.addEventListener("click", () => {
      close();
      entry.onPick();
    });
    menu.append(item);
  }
  host.append(menu);

  const a = anchor.getBoundingClientRect();
  const r = host.getBoundingClientRect();
  // Taille de mise en page (sans l'échelle d'entrée du menu).
  const m = { width: menu.offsetWidth, height: menu.offsetHeight };
  let top = a.bottom - r.top + 6;
  const above = top + m.height > r.height - 8;
  if (above) top = a.top - r.top - m.height - 6;
  let left = align === "end" ? a.right - r.left - m.width : a.left - r.left;
  left = Math.min(Math.max(8, left), r.width - m.width - 8);
  menu.style.top = `${top}px`;
  menu.style.left = `${left}px`;
  // Le menu grandit depuis son bouton : coin haut ou bas, côté aligné.
  menu.style.setProperty("--origin", `${above ? "bottom" : "top"} ${align === "end" ? "right" : "left"}`);
  anchor.setAttribute("aria-expanded", "true");

  const onDown = (e: PointerEvent): void => {
    if (!menu.contains(e.target as Node) && !anchor.contains(e.target as Node)) close();
  };
  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      close();
      anchor.focus();
    }
  };
  function close(): void {
    menu.remove();
    anchor.setAttribute("aria-expanded", "false");
    document.removeEventListener("pointerdown", onDown, true);
    document.removeEventListener("keydown", onKey, true);
    closeOpenMenu = null;
    openAnchor = null;
  }
  document.addEventListener("pointerdown", onDown, true);
  document.addEventListener("keydown", onKey, true);
  closeOpenMenu = close;
  menu.querySelector<HTMLButtonElement>(".menu-item:not(:disabled)")?.focus();
}

// ---------- Liste déroulante ----------

export interface Select<T extends string> {
  el: HTMLButtonElement;
  set(value: T): void;
  setOptions(options: Option<T>[]): void;
}

export function select<T extends string>(
  label: string,
  options: Option<T>[],
  value: T,
  onChange: (v: T) => void,
  /** `plain` : texte + chevron, sans cadre (menus des lignes de réglages). */
  variant: "box" | "plain" = "plain",
): Select<T> {
  const text = h("span", { class: "select-text" });
  const el = h("button", { class: `select is-${variant}`, type: "button", "aria-haspopup": "menu", "aria-label": label },
    text, icon("chevron", 14));
  let current = value;
  let opts = options;
  const render = (): void => {
    text.textContent = opts.find((o) => o.value === current)?.label ?? "";
  };
  render();
  el.addEventListener("click", () =>
    openMenu(el, opts.map((o) => ({
      label: o.label,
      checked: o.value === current,
      disabled: o.disabled,
      onPick: () => {
        if (o.value === current) return;
        current = o.value;
        render();
        onChange(o.value);
      },
    }))));
  return {
    el,
    set: (v) => { current = v; render(); },
    setOptions: (o) => { opts = o; render(); },
  };
}

// ---------- Étiquette ----------

export const tag = (text: string, kind: "plain" | "off" = "plain"): HTMLElement =>
  h("span", { class: `tag${kind === "off" ? " is-off" : ""}` }, text);

// ---------- Bouton icône ----------

export function iconButton(name: IconName, label: string, onClick: (el: HTMLButtonElement) => void): HTMLButtonElement {
  const el = h("button", { class: "icon-btn", type: "button", "aria-label": label, title: label }, icon(name, 17));
  el.addEventListener("click", () => onClick(el));
  return el;
}

// ---------- Notification éphémère ----------

let toastTimer = 0;

export function toast(host: HTMLElement, message: string, kind: "info" | "error" = "info"): void {
  host.querySelector(".toast")?.remove();
  const el = h("div", { class: `toast is-${kind}`, role: "status" },
    icon(kind === "error" ? "alert" : "check", 16), message);
  host.append(el);
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    el.classList.add("is-leaving");
    el.addEventListener("transitionend", () => el.remove(), { once: true });
    // Filet de sécurité si aucune transition ne se termine (fenêtre masquée, etc.).
    window.setTimeout(() => el.remove(), 400);
  }, 2600);
}

/**
 * Retour de copie : l'icône du bouton devient une coche un instant (fondu flouté), puis revient.
 * Remplace une notification : la confirmation reste là où l'on a cliqué.
 */
export function confirmCopy(button: HTMLButtonElement, original: IconName): void {
  const swap = (name: IconName, done: boolean): void => {
    button.classList.add("is-swapping");
    window.setTimeout(() => {
      button.replaceChildren(icon(name, 17));
      button.classList.toggle("is-done", done);
      button.classList.remove("is-swapping");
    }, 120);
  };
  swap("check", true);
  window.setTimeout(() => swap(original, false), 1400);
}

// ---------- Ligne de réglage ----------

/** Ligne de réglage : titre, description, contrôles à droite. */
export function settingRow(title: string, desc: string | HTMLElement | null, ...controls: HTMLElement[]): HTMLElement {
  return h("div", { class: "row" },
    h("div", { class: "row-text" },
      h("span", { class: "row-title" }, title),
      typeof desc === "string" ? h("span", { class: "row-desc" }, desc) : desc),
    h("div", { class: "row-ctl" }, ...controls));
}

// ---------- Débit ----------

/** Débit avec sa flèche (icône de la même famille que les autres, pas un caractère). */
export function rateLabel(dir: "down" | "up", text: string): HTMLElement {
  return h("span", { class: `rate is-${dir}` }, icon(dir === "down" ? "arrowDown" : "arrowUp", 12), text);
}
