//! Erreurs du moteur (messages en français, destinés à l'utilisateur).

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    /// Paramètres de configuration inutilisables.
    #[error("Configuration invalide : {0}")]
    Config(String),

    /// `WinDivert.dll` introuvable ou non chargeable.
    #[error("Impossible de charger WinDivert ({}) : {source}", .path.display())]
    DllLoad {
        path: PathBuf,
        source: libloading::Error,
    },

    /// Fonction absente de la DLL (mauvaise version ?).
    #[error("WinDivert est incompatible (fonction {name} absente) : {source}")]
    Symbol {
        name: &'static str,
        source: libloading::Error,
    },

    /// `WinDivertOpen` a échoué ; `code` est le `GetLastError`.
    #[error("Pilote réseau indisponible : {} (code {code})", driver_hint(.code))]
    DriverOpen { code: u32 },

    /// Le port du proxy TCP local n'a pas pu être ouvert.
    #[error("Port du proxy TCP indisponible : {0}")]
    Bind(std::io::Error),

    /// Création du runtime ou d'un thread impossible.
    #[error("Démarrage du moteur impossible : {0}")]
    Runtime(std::io::Error),
}

/// Explication courte d'un code d'erreur `WinDivertOpen` courant.
fn driver_hint(code: &u32) -> &'static str {
    match *code {
        2 => "fichier du pilote introuvable (WinDivert64.sys)",
        5 => "droits administrateur requis",
        87 => "filtre refusé par le pilote",
        577 => "signature du pilote refusée par Windows",
        654 => "pilote incompatible avec cette version de Windows",
        1058 => "pilote désactivé",
        1275 => "pilote bloqué par Windows ou un antivirus",
        _ => "erreur inattendue",
    }
}
