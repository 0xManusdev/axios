//! Assemblage de l'application : plugins, fenêtre, démarrage, arrêt.

use std::sync::Arc;

use tauri::{AppHandle, Manager, WindowEvent};

use pw_support::logging;

use crate::{commands, controller::Controller, stats, tray};

const MAIN_WINDOW: &str = "main";

/// Affiche et active la fenêtre principale.
pub fn show_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window(MAIN_WINDOW) else {
        log::warn!("fenêtre principale introuvable");
        return;
    };
    if let Err(e) = window.unminimize().and_then(|()| window.show()) {
        log::warn!("affichage de la fenêtre : {e}");
    }
    if let Err(e) = window.set_focus() {
        log::debug!("focus de la fenêtre : {e}");
    }
}

/// Quitte proprement : point d'accès arrêté, moteur fermé, puis sortie du processus.
pub async fn quit(app: &AppHandle) {
    let controller = Arc::clone(&*app.state::<Arc<Controller>>());
    controller.shutdown().await;
    app.exit(0);
}

pub fn run() {
    logging::init("partage-wifi.log", "axios");
    let minimized = std::env::args().any(|a| a == "--minimized");

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            log::info!("seconde instance : affichage de la fenêtre");
            show_main_window(app);
        }))
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_snapshot,
            commands::set_sharing,
            commands::configure_network,
            commands::get_sources,
            commands::set_source,
            commands::get_settings,
            commands::update_settings,
            commands::rename_device,
            commands::set_device_blocked,
            commands::set_device_limit,
            commands::get_usage,
            commands::quit_app,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let controller = Controller::new(handle.clone());
            app.manage(Arc::clone(&controller));
            tray::init(&handle)?;

            // Fermer = masquer dans la zone de notification (y compris Alt+F4).
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                let w = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        if let Err(e) = w.hide() {
                            log::warn!("masquage de la fenêtre : {e}");
                        }
                    }
                });
            }

            tauri::async_runtime::spawn(async move {
                controller.init().await;
                controller.spawn_poll();
                stats::spawn(Arc::clone(&controller));
                if !minimized {
                    show_main_window(&handle);
                }
                if controller.settings().share_on_launch {
                    log::info!("partage au lancement");
                    controller.set_sharing(true).await;
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!());

    if let Err(e) = result {
        log::error!("erreur fatale de l'application : {e}");
    }
}
