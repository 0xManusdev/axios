//! Détection de l'élévation du processus courant.

use windows::core::Owned;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `true` si le processus courant s'exécute avec un jeton administrateur élevé.
pub fn is_elevated() -> bool {
    let mut token = unsafe { Owned::new(HANDLE::default()) };
    // SAFETY: `token` reçoit un handle valide en cas de succès ; `Owned` le ferme à la sortie.
    if let Err(e) = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut *token) } {
        log::warn!("OpenProcessToken a échoué : {e}");
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: le tampon pointe sur `elevation` et sa taille est celle de `TOKEN_ELEVATION`.
    let res = unsafe {
        GetTokenInformation(
            *token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    match res {
        Ok(()) => elevation.TokenIsElevated != 0,
        Err(e) => {
            log::warn!("GetTokenInformation a échoué : {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn does_not_panic() {
        let _ = super::is_elevated();
    }
}
