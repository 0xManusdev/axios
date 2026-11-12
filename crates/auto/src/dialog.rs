//! Boîtes de dialogue natives (seule interface du partage automatique).

use windows::core::HSTRING;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_SETFOREGROUND,
    MB_YESNO, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE,
};

const TITLE: &str = "Partage Wi-Fi";

fn show(text: &str, style: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    // SAFETY: chaînes valides pendant l'appel, aucune fenêtre parente.
    unsafe {
        MessageBoxW(
            None,
            &HSTRING::from(text),
            &HSTRING::from(TITLE),
            style | MB_SETFOREGROUND,
        )
    }
}

pub fn info(text: &str) {
    show(text, MB_OK | MB_ICONINFORMATION);
}

pub fn error(text: &str) {
    show(text, MB_OK | MB_ICONERROR);
}

/// Question oui / non ; `true` pour « Oui ».
pub fn confirm(text: &str) -> bool {
    show(text, MB_YESNO | MB_ICONQUESTION) == IDYES
}
