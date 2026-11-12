//! Initialisation de l'apartment COM / WinRT du thread courant.

use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

/// Libère l'initialisation à la fin du thread, uniquement si on l'a effectuée nous-mêmes.
struct Guard(bool);

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: appariée à un `CoInitializeEx` réussi sur ce même thread.
            unsafe { CoUninitialize() };
        }
    }
}

thread_local! {
    static APARTMENT: Guard = {
        // SAFETY: appel sans pointeur ; le résultat est examiné ci-dessous.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // S_OK / S_FALSE : initialisé (ou déjà en MTA) -> on doit libérer.
        // RPC_E_CHANGED_MODE : le thread est déjà en STA, on l'utilise tel quel sans le toucher.
        if hr.is_err() {
            log::debug!("apartment COM déjà initialisé dans un autre mode ({hr:?}), conservé");
        }
        Guard(hr.is_ok())
    };
}

/// S'assure que le thread courant a un apartment COM (MTA par défaut) ; sans effet s'il en a déjà un.
pub(crate) fn ensure() {
    APARTMENT.with(|_| {});
}
