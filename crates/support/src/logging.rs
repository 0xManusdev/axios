//! Journal fichier avec rotation simple (`<nom>.log` → `<nom>.log.1`).

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use log::{LevelFilter, Log, Metadata, Record};

use crate::paths;

const MAX_BYTES: u64 = 1024 * 1024;

struct Sink {
    file: File,
    path: PathBuf,
    written: u64,
}

impl Sink {
    fn open(path: PathBuf) -> std::io::Result<Self> {
        let written = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let mut sink = Sink {
            file,
            path,
            written,
        };
        if sink.written > MAX_BYTES {
            sink.rotate()?;
        }
        Ok(sink)
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let old = self.path.with_extension("log.1");
        // Le plus ancien journal est écrasé ; l'échec d'un renommage n'est pas bloquant.
        let _ = fs::remove_file(&old);
        let _ = fs::rename(&self.path, &old);
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }

    fn write_line(&mut self, line: &str) {
        if self.written > MAX_BYTES && self.rotate().is_err() {
            return;
        }
        if self.file.write_all(line.as_bytes()).is_ok() {
            self.written += line.len() as u64;
        }
    }
}

struct FileLogger {
    sink: Mutex<Sink>,
    level: LevelFilter,
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if metadata.level() > self.level {
            return false;
        }
        // Les bibliothèques graphiques sont bavardes : avertissements seulement.
        let noisy = ["tao", "wry", "tauri", "mio", "tokio"]
            .iter()
            .any(|p| metadata.target().starts_with(p));
        !noisy || metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} {} - {}\n",
            timestamp(),
            record.level(),
            record.target(),
            record.args()
        );
        #[cfg(debug_assertions)]
        eprint!("{line}");
        self.sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_line(&line);
    }

    fn flush(&self) {
        let _ = self
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .file
            .flush();
    }
}

/// Initialise le journal `file_name` (dans `%LOCALAPPDATA%\PartageWiFi\logs`) et y consigne
/// le démarrage de `label`. Sans effet (silencieux) si le fichier est inaccessible.
pub fn init(file_name: &str, label: &str) {
    let dir = paths::logs_dir();
    let sink = fs::create_dir_all(&dir)
        .and_then(|()| Sink::open(dir.join(file_name)))
        .ok();
    let Some(sink) = sink else {
        return;
    };
    let level = if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let logger = Box::new(FileLogger {
        sink: Mutex::new(sink),
        level,
    });
    if log::set_boxed_logger(logger).is_ok() {
        log::set_max_level(level);
    }
    std::panic::set_hook(Box::new(|info| log::error!("panique : {info}")));
    log::info!("démarrage de {label} {}", env!("CARGO_PKG_VERSION"));
}

/// Horodatage UTC ISO 8601 (secondes), sans dépendance de calendrier.
fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Algorithme de Howard Hinnant : jours depuis 1970-01-01 → date civile.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::civil_from_days;

    #[test]
    fn dates_civiles() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }
}
