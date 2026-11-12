//! Commandes Tauri (CONTRACT-V2.md §3). Les erreurs sont des messages français prêts à afficher.

use std::sync::Arc;

use pw_winsys::hotspot::{Band, Source};
use tauri::{AppHandle, State};

use crate::{
    controller::{Controller, Snapshot},
    history::{Range, Usage},
    settings::{Settings, SettingsPatch},
};

type Ctl<'a> = State<'a, Arc<Controller>>;

#[tauri::command]
pub fn get_snapshot(controller: Ctl<'_>) -> Snapshot {
    controller.snapshot()
}

#[tauri::command]
pub async fn set_sharing(controller: Ctl<'_>, on: bool) -> Result<Snapshot, String> {
    Ok(controller.set_sharing(on).await)
}

#[tauri::command]
pub async fn configure_network(
    controller: Ctl<'_>,
    ssid: String,
    passphrase: String,
    band: Band,
) -> Result<Snapshot, String> {
    controller
        .configure(ssid, passphrase, band)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_sources(controller: Ctl<'_>) -> Result<Vec<Source>, String> {
    controller.sources().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_source(controller: Ctl<'_>, id: String) -> Result<Snapshot, String> {
    controller.set_source(id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_settings(controller: Ctl<'_>) -> Settings {
    controller.settings()
}

#[tauri::command]
pub async fn update_settings(
    controller: Ctl<'_>,
    patch: SettingsPatch,
) -> Result<Settings, String> {
    controller
        .update_settings(patch)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn rename_device(controller: Ctl<'_>, id: String, alias: String) -> Result<(), String> {
    controller
        .rename_device(&id, &alias)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_device_blocked(
    controller: Ctl<'_>,
    id: String,
    blocked: bool,
) -> Result<(), String> {
    controller
        .set_device_blocked(&id, blocked)
        .await
        .map_err(|e| e.to_string())
}

/// `limit` en Mb/s, `null` = réglage par défaut.
#[tauri::command]
pub async fn set_device_limit(
    controller: Ctl<'_>,
    id: String,
    limit: Option<f64>,
) -> Result<(), String> {
    controller
        .set_device_limit(&id, limit)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_usage(controller: Ctl<'_>, range: Range) -> Usage {
    controller.usage(range)
}

#[tauri::command]
pub async fn quit_app(app: AppHandle) -> Result<(), String> {
    crate::app::quit(&app).await;
    Ok(())
}
