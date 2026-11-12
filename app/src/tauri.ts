import type { Api } from "./api";
import type { Settings, Snapshot, Source, Stats, Usage } from "./types";

/** Vrai dans la fenêtre de l'app, faux dans un navigateur (maquette). */
export const isTauri = (): boolean => "__TAURI_INTERNALS__" in window;

/** Pont vers la coquille Rust : commandes et événements de CONTRACT-V2.md §3. */
export async function createTauriApi(): Promise<Api> {
  const [{ invoke }, { listen }, { getCurrentWindow }, { getCurrentWebview }] = await Promise.all([
    import("@tauri-apps/api/core"),
    import("@tauri-apps/api/event"),
    import("@tauri-apps/api/window"),
    import("@tauri-apps/api/webview"),
  ]);

  const on = <T>(event: string, cb: (payload: T) => void): (() => void) => {
    const off = listen<T>(event, (e) => cb(e.payload));
    return () => void off.then((f) => f());
  };

  return {
    getSnapshot: () => invoke<Snapshot>("get_snapshot"),
    setSharing: (on) => invoke<Snapshot>("set_sharing", { on }),
    configureNetwork: (ssid, passphrase, band) => invoke<Snapshot>("configure_network", { ssid, passphrase, band }),
    getSources: () => invoke<Source[]>("get_sources"),
    setSource: (id) => invoke<Snapshot>("set_source", { id }),
    getSettings: () => invoke<Settings>("get_settings"),
    updateSettings: (patch) => invoke<Settings>("update_settings", { patch }),
    renameDevice: (id, alias) => invoke<void>("rename_device", { id, alias }),
    setDeviceBlocked: (id, blocked) => invoke<void>("set_device_blocked", { id, blocked }),
    setDeviceLimit: (id, limit) => invoke<void>("set_device_limit", { id, limit }),
    getUsage: (range) => invoke<Usage>("get_usage", { range }),
    onSnapshot: (cb) => on<Snapshot>("snapshot", cb),
    onStats: (cb) => on<Stats>("stats", cb),
    setZoom: (scale) => void getCurrentWebview().setZoom(scale),
    minimize: () => void getCurrentWindow().minimize(),
    hide: () => void getCurrentWindow().hide(),
    quit: () => void invoke("quit_app"),
  };
}
