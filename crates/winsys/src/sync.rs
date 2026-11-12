//! Objets noyau nommés, partagés entre processus : verrou d'exclusivité et signal.

use std::time::Duration;

use windows::core::{Owned, HSTRING};
use windows::Win32::Foundation::{
    GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, HANDLE, WAIT_OBJECT_0,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE,
};

use crate::error::{Context, Result};

/// Verrou d'exclusivité entre processus.
///
/// Il est tenu tant que l'objet vit : sa destruction, ou la fin du processus (même brutale),
/// le libère. On s'appuie sur l'existence de l'objet noyau, pas sur sa possession : aucun
/// état « abandonné » à gérer.
pub struct NamedLock {
    _handle: Owned<HANDLE>,
}

impl NamedLock {
    /// Prend le verrou `name` ; `None` s'il est déjà tenu (par ce processus ou un autre).
    pub fn try_acquire(name: &str) -> Result<Option<Self>> {
        let wide = HSTRING::from(name);
        // SAFETY: `wide` vit pendant l'appel ; le handle renvoyé est confié à `Owned`.
        let handle = unsafe { CreateMutexW(None, false, &wide) }.ctx("Création d'un verrou")?;
        // SAFETY: lu immédiatement après `CreateMutexW`, sans appel système intermédiaire.
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        // SAFETY: handle valide, possédé par nous seuls ; fermé une fois `Owned` détruit.
        let handle = unsafe { Owned::new(handle) };
        Ok((!existed).then_some(NamedLock { _handle: handle }))
    }

    /// `true` si le verrou `name` est tenu par un processus.
    pub fn is_held(name: &str) -> Result<bool> {
        Ok(Self::try_acquire(name)?.is_none())
    }
}

// SAFETY: un handle de mutex noyau n'est pas lié à un thread ; on ne fait que le fermer.
unsafe impl Send for NamedLock {}
// SAFETY: aucune méthode `&self` : rien n'est partagé.
unsafe impl Sync for NamedLock {}

/// Signal entre processus (événement à réinitialisation automatique).
pub struct NamedEvent {
    handle: Owned<HANDLE>,
}

// SAFETY: un handle d'événement noyau s'utilise depuis n'importe quel thread ;
// `WaitForSingleObject` et `CloseHandle` sont sûrs en concurrence.
unsafe impl Send for NamedEvent {}
// SAFETY: idem.
unsafe impl Sync for NamedEvent {}

impl NamedEvent {
    /// Crée (ou ouvre) l'événement `name`, non signalé à la création.
    pub fn create(name: &str) -> Result<Self> {
        let wide = HSTRING::from(name);
        // SAFETY: `wide` vit pendant l'appel ; le handle renvoyé est confié à `Owned`.
        let handle =
            unsafe { CreateEventW(None, false, false, &wide) }.ctx("Création d'un signal")?;
        // SAFETY: handle valide, possédé par nous seuls.
        Ok(NamedEvent {
            handle: unsafe { Owned::new(handle) },
        })
    }

    /// Attend le signal au plus `timeout` ; `true` s'il a été reçu.
    pub fn wait(&self, timeout: Duration) -> bool {
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: handle valide pendant toute la vie de `self`.
        let event = unsafe { WaitForSingleObject(*self.handle, ms) };
        event == WAIT_OBJECT_0
    }

    /// Émet le signal `name` ; `false` si personne ne l'écoute (événement inexistant).
    pub fn signal(name: &str) -> Result<bool> {
        let wide = HSTRING::from(name);
        // SAFETY: `wide` vit pendant l'appel.
        let handle = match unsafe { OpenEventW(EVENT_MODIFY_STATE, false, &wide) } {
            Ok(h) => h,
            Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() => return Ok(false),
            Err(e) => return Err(e).ctx("Ouverture d'un signal"),
        };
        // SAFETY: handle valide renvoyé par `OpenEventW`, confié à `Owned`.
        let handle = unsafe { Owned::new(handle) };
        // SAFETY: handle valide, ouvert avec le droit `EVENT_MODIFY_STATE`.
        unsafe { SetEvent(*handle) }.ctx("Émission d'un signal")?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Espace de noms de la session : pas besoin des droits administrateur.
    const LOCK: &str = r"Local\PartageWiFi.Test.Verrou";
    const EVENT: &str = r"Local\PartageWiFi.Test.Signal";

    #[test]
    fn verrou_exclusif_puis_libere() {
        let held = NamedLock::try_acquire(LOCK).unwrap().expect("verrou libre");
        assert!(NamedLock::try_acquire(LOCK).unwrap().is_none());
        assert!(NamedLock::is_held(LOCK).unwrap());
        drop(held);
        assert!(!NamedLock::is_held(LOCK).unwrap());
    }

    #[test]
    fn signal_recu_une_fois() {
        assert!(!NamedEvent::signal(EVENT).unwrap(), "personne n'écoute");
        let event = NamedEvent::create(EVENT).unwrap();
        assert!(!event.wait(Duration::from_millis(10)));
        assert!(NamedEvent::signal(EVENT).unwrap());
        assert!(event.wait(Duration::from_millis(10)));
        // Réinitialisation automatique.
        assert!(!event.wait(Duration::from_millis(10)));
    }
}
