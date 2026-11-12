//! Emplacements des fichiers de l'application.

use std::path::PathBuf;

/// `%LOCALAPPDATA%\PartageWiFi` (repli sur le dossier temporaire).
pub fn app_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("PartageWiFi")
}

pub fn logs_dir() -> PathBuf {
    app_dir().join("logs")
}

pub fn windivert_dir() -> PathBuf {
    app_dir().join("windivert")
}
