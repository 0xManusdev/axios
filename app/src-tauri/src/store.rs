//! Fichiers JSON de l'application : lecture tolérante, écriture atomique.
//!
//! Un fichier absent ou illisible donne les valeurs par défaut (avec un avertissement au
//! journal pour un fichier corrompu, dont une copie est conservée). L'écriture passe par un
//! fichier temporaire renommé ensuite : un arrêt brutal ne laisse jamais un fichier tronqué.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
};

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};

use crate::error::blocking;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Écrit `bytes` dans `path` de façon atomique (temporaire + renommage).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // Sous Windows, `rename` remplace la destination existante.
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Lit et désérialise `path` ; `None` si absent ou illisible (avertissement au journal).
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            log::debug!("{} absent : valeurs par défaut", path.display());
            return None;
        }
        Err(e) => {
            log::warn!(
                "lecture de {} impossible ({e}) : valeurs par défaut",
                path.display()
            );
            return None;
        }
    };
    match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
        Ok(value) => Some(value),
        Err(e) => {
            log::warn!("{} corrompu ({e}) : valeurs par défaut", path.display());
            let mut backup = path.as_os_str().to_owned();
            backup.push(".corrompu");
            if let Err(e) = fs::copy(path, PathBuf::from(backup)) {
                log::debug!("copie du fichier corrompu impossible : {e}");
            }
            None
        }
    }
}

/// Désérialisation d'un champ qui retombe sur la valeur par défaut si elle est invalide :
/// une valeur inattendue ne fait pas perdre le reste du fichier.
pub fn lenient<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
}

/// Données persistées dans un fichier JSON, protégées par un verrou `std`.
pub struct JsonFile<T> {
    path: PathBuf,
    data: Mutex<T>,
    /// Numéro de la dernière version sérialisée.
    version: AtomicU64,
    /// Numéro de la version présente sur disque ; le verrou sérialise aussi les écritures.
    written: Arc<Mutex<u64>>,
}

impl<T: Serialize + DeserializeOwned> JsonFile<T> {
    /// Charge `path`, ou `default()` s'il est absent ou corrompu. Le booléen indique si le
    /// fichier a été lu.
    pub fn load_or(path: PathBuf, default: impl FnOnce() -> T) -> (Self, bool) {
        let loaded = read_json(&path);
        let found = loaded.is_some();
        let file = JsonFile {
            data: Mutex::new(loaded.unwrap_or_else(default)),
            path,
            version: AtomicU64::new(0),
            written: Arc::new(Mutex::new(0)),
        };
        (file, found)
    }

    /// Lecture sous verrou.
    pub fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(&lock(&self.data))
    }

    /// Modification sous verrou, sans écriture (appeler [`JsonFile::save`] ensuite).
    pub fn modify<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut lock(&self.data))
    }

    /// Sérialise l'état courant (version numérotée, sous le verrou des données).
    fn serialize(&self) -> Option<(u64, Vec<u8>)> {
        let data = lock(&self.data);
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;
        match serde_json::to_vec_pretty(&*data) {
            Ok(bytes) => Some((version, bytes)),
            Err(e) => {
                log::error!("sérialisation de {} : {e}", self.path.display());
                None
            }
        }
    }

    /// Écrit l'état courant sur disque, hors du runtime asynchrone. Une écriture plus
    /// ancienne qu'une autre déjà faite est abandonnée. Les erreurs sont consignées.
    pub async fn save(&self) {
        let Some((version, bytes)) = self.serialize() else {
            return;
        };
        let path = self.path.clone();
        let written = Arc::clone(&self.written);
        let result = blocking(move || write_version(&path, &written, version, &bytes)).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::error!("écriture de {} : {e}", self.path.display()),
            Err(e) => log::error!("écriture de {} : {e}", self.path.display()),
        }
    }

    /// Comme [`JsonFile::save`], de façon synchrone (arrêt de l'application).
    pub fn save_now(&self) {
        let Some((version, bytes)) = self.serialize() else {
            return;
        };
        if let Err(e) = write_version(&self.path, &self.written, version, &bytes) {
            log::error!("écriture de {} : {e}", self.path.display());
        }
    }
}

fn write_version(path: &Path, written: &Mutex<u64>, version: u64, bytes: &[u8]) -> io::Result<()> {
    let mut on_disk = lock(written);
    if version <= *on_disk {
        return Ok(());
    }
    write_atomic(path, bytes)?;
    *on_disk = version;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct Demo {
        #[serde(deserialize_with = "lenient")]
        n: u32,
        s: String,
    }

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("axios-test-{}", std::process::id()));
        dir.join(name)
    }

    #[test]
    fn champ_invalide_retombe_sur_le_defaut() {
        let d: Demo = serde_json::from_str(r#"{"n":"abc","s":"x","inconnu":1}"#).unwrap();
        assert_eq!(
            d,
            Demo {
                n: 0,
                s: "x".into()
            }
        );
        let d: Demo = serde_json::from_str("{}").unwrap();
        assert_eq!(d, Demo::default());
    }

    #[test]
    fn ecriture_atomique_et_relecture() {
        let path = temp_path("demo.json");
        let (file, found) = JsonFile::<Demo>::load_or(path.clone(), Demo::default);
        assert!(!found);
        file.modify(|d| d.n = 7);
        file.save_now();
        let (again, found) = JsonFile::<Demo>::load_or(path.clone(), Demo::default);
        assert!(found);
        assert_eq!(again.read(|d| d.n), 7);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn fichier_corrompu_donne_le_defaut() {
        let path = temp_path("corrompu.json");
        write_atomic(&path, b"{ pas du json").unwrap();
        let (file, found) = JsonFile::<Demo>::load_or(path.clone(), || Demo {
            n: 3,
            s: String::new(),
        });
        assert!(!found);
        assert_eq!(file.read(|d| d.n), 3);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn version_ancienne_non_ecrite() {
        let path = temp_path("versions.json");
        let written = Mutex::new(0);
        write_version(&path, &written, 2, b"2").unwrap();
        write_version(&path, &written, 1, b"1").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "2");
        let _ = fs::remove_file(&path);
    }
}
