//! Coquille Tauri d'« axios » (ex-« Partage Wi-Fi »).

mod app;
mod blocklist;
mod clock;
mod commands;
mod controller;
mod devices;
mod error;
mod history;
mod policy;
mod settings;
mod stats;
mod store;
mod tray;

pub use app::run;
