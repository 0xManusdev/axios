//! Icône de la zone de notification et son menu.

use std::sync::Arc;

use tauri::{
    image::Image,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

use crate::{
    app,
    controller::{Controller, Snapshot, Status},
};

const TRAY_ID: &str = "main";
const ID_OPEN: &str = "open";
const ID_TOGGLE: &str = "toggle";
const ID_QUIT: &str = "quit";

const ICON_IDLE: &[u8] = include_bytes!("../icons/tray-idle.png");
const ICON_ACTIVE: &[u8] = include_bytes!("../icons/tray-active.png");

/// Éléments modifiables au fil de l'état.
struct TrayState {
    toggle: MenuItem<tauri::Wry>,
    tray: TrayIcon,
}

pub fn init(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, ID_OPEN, "Ouvrir", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, ID_TOGGLE, "Activer le partage", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, ID_QUIT, "Quitter", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &toggle, &separator, &quit])?;

    let tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(Image::from_bytes(ICON_IDLE)?)
        .tooltip("axios")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(on_menu_event)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                app::show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    app.manage(TrayState { toggle, tray });
    Ok(())
}

fn on_menu_event(app: &AppHandle, event: MenuEvent) {
    match event.id().as_ref() {
        ID_OPEN => app::show_main_window(app),
        ID_TOGGLE => {
            let controller = Arc::clone(&*app.state::<Arc<Controller>>());
            tauri::async_runtime::spawn(async move {
                let on = controller.snapshot().status != Status::On;
                controller.set_sharing(on).await;
            });
        }
        ID_QUIT => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move { app::quit(&app).await });
        }
        _ => {}
    }
}

/// Met à jour libellé du menu, infobulle et icône selon l'instantané.
pub fn refresh(app: &AppHandle, snapshot: &Snapshot) {
    let Some(state) = app.try_state::<TrayState>() else {
        return;
    };
    let (label, enabled, tooltip) = match snapshot.status {
        Status::On => ("Désactiver le partage", true, "axios : actif"),
        Status::Starting => ("Démarrage…", false, "axios : démarrage"),
        Status::Stopping => ("Arrêt…", false, "axios : arrêt"),
        Status::Off => ("Activer le partage", true, "axios : inactif"),
        Status::Error => ("Activer le partage", true, "axios : erreur"),
    };
    let icon = if snapshot.status == Status::On {
        ICON_ACTIVE
    } else {
        ICON_IDLE
    };
    if let Err(e) = state.toggle.set_text(label) {
        log::debug!("menu : {e}");
    }
    if let Err(e) = state.toggle.set_enabled(enabled) {
        log::debug!("menu : {e}");
    }
    if let Err(e) = state.tray.set_tooltip(Some(tooltip)) {
        log::debug!("infobulle : {e}");
    }
    match Image::from_bytes(icon) {
        Ok(image) => {
            if let Err(e) = state.tray.set_icon(Some(image)) {
                log::debug!("icône : {e}");
            }
        }
        Err(e) => log::debug!("icône : {e}"),
    }
}
