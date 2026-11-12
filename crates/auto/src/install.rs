//! Activation et désactivation du partage automatique.
//!
//! Activer : copie de l'exécutable dans `%LOCALAPPDATA%\PartageWiFi\auto\` (le fichier téléchargé
//! peut être déplacé ou supprimé ensuite), tâche planifiée à l'ouverture de session, lancement.
//! Désactiver : suppression de la tâche, arrêt de l'instance, nettoyage.

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use pw_support::paths;
use pw_winsys::{
    autostart, firewall,
    sync::{NamedEvent, NamedLock},
    WinsysError,
};

use crate::{BACKGROUND_ARG, FIREWALL_RULE, INSTANCE_LOCK, STOP_SIGNAL, TASK_NAME};

const EXE_NAME: &str = "partage-wifi-auto.exe";
/// Délai laissé à l'instance pour démarrer.
const START_TIMEOUT: Duration = Duration::from_secs(10);
/// Délai laissé à l'instance pour s'arrêter (arrêt du moteur compris).
const STOP_TIMEOUT: Duration = Duration::from_secs(20);
const WAIT_STEP: Duration = Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("{0}")]
    Winsys(#[from] WinsysError),
    #[error("Fichiers inaccessibles : {0}")]
    Io(#[from] io::Error),
    #[error("Le partage automatique n'a pas démarré. Le journal en indique la raison.")]
    NotStarted,
    #[error("Le partage automatique ne répond pas. Redémarrez le PC pour terminer.")]
    NotStopped,
}

/// Dossier d'installation de l'exécutable.
pub fn install_dir() -> PathBuf {
    paths::app_dir().join("auto")
}

/// `true` si une instance tourne.
pub fn is_running() -> Result<bool, InstallError> {
    Ok(NamedLock::is_held(INSTANCE_LOCK)?)
}

/// Installe, enregistre au démarrage et lance l'instance d'arrière-plan.
pub fn enable() -> Result<(), InstallError> {
    let exe = copy_self()?;
    autostart::set(TASK_NAME, true, &exe, BACKGROUND_ARG)?;
    Command::new(&exe)
        .arg(BACKGROUND_ARG)
        .current_dir(install_dir())
        .spawn()?;
    if !wait_until(START_TIMEOUT, || is_running().unwrap_or(false)) {
        return Err(InstallError::NotStarted);
    }
    log::info!("partage automatique activé ({})", exe.display());
    Ok(())
}

/// Désenregistre puis arrête l'instance d'arrière-plan, et nettoie.
pub fn disable() -> Result<(), InstallError> {
    // D'abord la tâche : même si l'arrêt échoue, rien ne sera relancé.
    autostart::set(TASK_NAME, false, Path::new(""), "")?;
    if !NamedEvent::signal(STOP_SIGNAL)? {
        log::warn!("signal d'arrêt sans destinataire");
    }
    if !wait_until(STOP_TIMEOUT, || !is_running().unwrap_or(true)) {
        return Err(InstallError::NotStopped);
    }
    if let Err(e) = firewall::remove_rule(FIREWALL_RULE) {
        log::warn!("règle de pare-feu : {e}");
    }
    remove_installed_copy();
    log::info!("partage automatique désactivé");
    Ok(())
}

/// Copie l'exécutable courant dans le dossier d'installation (sauf s'il y est déjà).
fn copy_self() -> Result<PathBuf, InstallError> {
    let current = std::env::current_exe()?;
    let dir = install_dir();
    fs::create_dir_all(&dir)?;
    let target = dir.join(EXE_NAME);
    if !same_file(&current, &target) {
        fs::copy(&current, &target)?;
    }
    Ok(target)
}

/// Supprime la copie installée, sauf si c'est l'exécutable en cours.
fn remove_installed_copy() {
    let target = install_dir().join(EXE_NAME);
    let is_current = std::env::current_exe().is_ok_and(|current| same_file(&current, &target));
    if is_current {
        return;
    }
    if let Err(e) = fs::remove_file(&target) {
        if e.kind() != io::ErrorKind::NotFound {
            log::warn!("suppression de {} : {e}", target.display());
        }
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Attend que `done` soit vrai, au plus `timeout`.
fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(WAIT_STEP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meme_fichier() {
        let exe = std::env::current_exe().unwrap();
        assert!(same_file(&exe, &exe));
        assert!(!same_file(&exe, &exe.with_extension("absent")));
    }

    #[test]
    fn attente_bornee() {
        assert!(wait_until(Duration::ZERO, || true));
        assert!(!wait_until(Duration::ZERO, || false));
        let mut n = 0;
        assert!(wait_until(Duration::from_secs(5), || {
            n += 1;
            n == 3
        }));
    }
}
