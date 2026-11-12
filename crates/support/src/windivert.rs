//! Binaires WinDivert embarqués, extraits dans `%LOCALAPPDATA%\PartageWiFi\windivert\`.

use std::{fs, io, path::Path, path::PathBuf};

use crate::paths;

const DLL: &[u8] = include_bytes!("../../../vendor/windivert/WinDivert.dll");
const SYS: &[u8] = include_bytes!("../../../vendor/windivert/WinDivert64.sys");

/// Extrait les binaires s'ils manquent ou diffèrent ; renvoie le chemin de `WinDivert.dll`.
pub fn ensure_extracted() -> io::Result<PathBuf> {
    let dir = paths::windivert_dir();
    fs::create_dir_all(&dir)?;
    let dll = dir.join("WinDivert.dll");
    write_if_different(&dll, DLL)?;
    write_if_different(&dir.join("WinDivert64.sys"), SYS)?;
    Ok(dll)
}

fn write_if_different(path: &Path, content: &[u8]) -> io::Result<()> {
    if fs::read(path).is_ok_and(|existing| existing == content) {
        return Ok(());
    }
    log::info!("extraction de {}", path.display());
    fs::write(path, content)
}
