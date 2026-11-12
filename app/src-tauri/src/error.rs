//! Erreurs de la coquille, converties en messages français à la frontière des commandes.

use pw_engine::EngineError;
use pw_winsys::WinsysError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Winsys(#[from] WinsysError),
    #[error("Pilote réseau indisponible : {0}")]
    Engine(#[from] EngineError),
    #[error("Fichiers du pilote réseau inaccessibles : {0}")]
    Io(#[from] std::io::Error),
    #[error("Le réseau de partage est introuvable. Réessayez dans un instant.")]
    InterfaceNotFound,
    #[error("Le partage automatique est actif : désactivez-le pour utiliser l'application.")]
    EngineBusy,
    #[error("Opération interrompue ({0})")]
    Task(String),
    /// Valeur refusée (message prêt à afficher).
    #[error("{0}")]
    Invalid(String),
}

/// Exécute une closure bloquante hors du runtime asynchrone.
pub async fn blocking<T, F>(f: F) -> Result<T, AppError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Task(e.to_string()))
}

/// Comme [`blocking`], pour une closure faillible dont l'erreur se convertit en [`AppError`].
pub async fn blocking_try<T, E, F>(f: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: Into<AppError> + Send + 'static,
{
    blocking(f).await?.map_err(Into::into)
}
