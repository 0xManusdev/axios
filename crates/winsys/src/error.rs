//! Erreur commune à toutes les intégrations.

/// Erreur d'une intégration système. Le `Display` est destiné à l'utilisateur (français, court) ;
/// le détail technique (HRESULT) reste accessible via `source()`.
#[derive(Debug, thiserror::Error)]
pub enum WinsysError {
    /// Aucun profil de connexion internet : le point d'accès ne peut pas être piloté.
    #[error("Aucune connexion internet")]
    NoInternet,
    /// SSID refusé par la validation.
    #[error("Nom du réseau invalide : {0}")]
    InvalidSsid(&'static str),
    /// Mot de passe refusé par la validation.
    #[error("Mot de passe invalide : {0}")]
    InvalidPassphrase(&'static str),
    /// Bande de fréquence non prise en charge par la carte Wi-Fi.
    #[error("Bande Wi-Fi non prise en charge par cet appareil")]
    UnsupportedBand,
    /// Windows a refusé ou échoué l'opération sur le point d'accès.
    #[error("Point d'accès : {0}")]
    Tethering(String),
    /// Chemin non utilisable (par exemple non convertible en texte).
    #[error("Chemin invalide : {0}")]
    InvalidPath(String),
    /// Échec d'un appel Windows (COM / WinRT / Win32).
    #[error("{context} : erreur Windows 0x{:08X}", .source.code().0)]
    Windows {
        /// Action en cours, en français.
        context: &'static str,
        /// Erreur d'origine (conserve le HRESULT).
        #[source]
        source: windows::core::Error,
    },
}

/// Alias de résultat du crate.
pub type Result<T> = std::result::Result<T, WinsysError>;

/// Adaptateur : `.ctx("…")` convertit une erreur `windows` en [`WinsysError::Windows`].
pub(crate) trait Context<T> {
    fn ctx(self, context: &'static str) -> Result<T>;
}

impl<T> Context<T> for windows::core::Result<T> {
    fn ctx(self, context: &'static str) -> Result<T> {
        self.map_err(|source| WinsysError::Windows { context, source })
    }
}
