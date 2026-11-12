const PATHS = {
  home: '<path d="M4 10.5 12 4l8 6.5V19a1.5 1.5 0 0 1-1.5 1.5H15v-5.5H9v5.5H5.5A1.5 1.5 0 0 1 4 19z"/>',
  devices: '<rect x="3" y="5" width="13" height="10" rx="2"/><path d="M6 18.5h7"/><rect x="17.5" y="9" width="4" height="10" rx="1.4"/>',
  activity: '<path d="M3.5 19.5h17"/><path d="M6.5 16V11M11 16V6.5M15.5 16v-6M20 16V8.5"/>',
  settings: '<path d="M4 7h9M19 7h1M4 17h1M11 17h9"/><circle cx="16" cy="7" r="2.4"/><circle cx="8" cy="17" r="2.4"/>',
  wifi: '<path d="M2.5 9a14 14 0 0 1 19 0"/><path d="M5.5 12.5a9.5 9.5 0 0 1 13 0"/><path d="M8.7 16a5 5 0 0 1 6.6 0"/><circle cx="12" cy="19.4" r="1" fill="currentColor" stroke="none"/>',
  ethernet: '<rect x="5" y="4" width="14" height="11" rx="2"/><path d="M9 15v4h6v-4M9 8v3M12 8v3M15 8v3"/>',
  cellular: '<path d="M5 19v-3M9.5 19v-6M14 19v-9M18.5 19V5"/>',
  minimize: '<path d="M6 12h12"/>',
  close: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  eye: '<path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2.6"/><path d="M5 15V7.5A2.5 2.5 0 0 1 7.5 5H15"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  pencil: '<path d="M4 20l1-4L16.5 4.5a2.1 2.1 0 0 1 3 3L8 19z"/><path d="M14.5 6.5l3 3"/>',
  qr: '<rect x="4" y="4" width="6.5" height="6.5" rx="1.4"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.4"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.4"/><path d="M14 14h3v3h-3zM20 14v3M17 20h3"/>',
  arrowDown: '<path d="M12 5v14M6 13l6 6 6-6"/>',
  arrowUp: '<path d="M12 19V5M6 11l6-6 6 6"/>',
  phone: '<rect x="7" y="3" width="10" height="18" rx="2.6"/><path d="M11 18h2"/>',
  laptop: '<rect x="5" y="5" width="14" height="10" rx="1.8"/><path d="M3 18.5h18"/>',
  tablet: '<rect x="5" y="3" width="14" height="18" rx="2.4"/><path d="M11 18h2"/>',
  tv: '<rect x="3" y="5" width="18" height="12" rx="2"/><path d="M9 20.5h6"/>',
  chip: '<rect x="6" y="6" width="12" height="12" rx="2.4"/><path d="M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3"/>',
  power: '<path d="M12 3.5v8"/><path d="M6.6 7.4a7.8 7.8 0 1 0 10.8 0"/>',
  chevron: '<path d="M7.5 10l4.5 4.5 4.5-4.5"/>',
  more: '<circle cx="6" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="18" cy="12" r="1.3" fill="currentColor" stroke="none"/>',
  alert: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5M12 16v.01"/>',
  shield: '<path d="M12 3.5 5 6.2v5.3c0 4.4 3 7.6 7 9 4-1.4 7-4.6 7-9V6.2z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
  gauge: '<path d="M4.5 17a8.5 8.5 0 1 1 15 0"/><path d="M12 13.5l4-4"/>',
  ban: '<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
  lock: '<rect x="5" y="10.5" width="14" height="9.5" rx="2.6"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
  arrowLeft: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.8v.01"/>',
  display: '<rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M9 20h6M12 16.5V20"/>',
  logout: '<path d="M14 4.5h3.5A1.5 1.5 0 0 1 19 6v12a1.5 1.5 0 0 1-1.5 1.5H14"/><path d="M10 8l-4 4 4 4M6 12h9"/>',
} as const;

export type IconName = keyof typeof PATHS;

export function icon(name: IconName, size = 18): SVGSVGElement {
  const tpl = document.createElement("template");
  tpl.innerHTML =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${size}" height="${size}" ` +
    `fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" ` +
    `aria-hidden="true" focusable="false">${PATHS[name]}</svg>`;
  return tpl.content.firstElementChild as SVGSVGElement;
}
