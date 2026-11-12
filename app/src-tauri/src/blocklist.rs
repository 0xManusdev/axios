//! Bloqueur de publicités : liste StevenBlack (`blocklist.txt`), téléchargée à l'activation
//! puis rafraîchie après 7 jours, et petite liste de secours embarquée en attendant (ou si le
//! téléchargement échoue). La liste n'est analysée qu'une fois puis partagée (`Arc`).

use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};

use pw_engine::Blocklist;

use crate::store::{lock, write_atomic};

/// Liste « hosts » unifiée de StevenBlack (publicités et logiciels malveillants).
pub const URL: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
/// Âge au-delà duquel la liste est téléchargée à nouveau.
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Délai maximal d'un téléchargement.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(90);
/// En dessous, un fichier téléchargé est jugé invalide (page d'erreur, contenu tronqué…).
const MIN_DOMAINS: usize = 1000;

/// Liste de secours : régies publicitaires et traqueurs parmi les plus répandus.
const FALLBACK: &str = "\
# Liste de secours d'axios (régies publicitaires et traqueurs courants)
doubleclick.net
googlesyndication.com
googleadservices.com
googletagservices.com
google-analytics.com
adservice.google.com
adnxs.com
adsrvr.org
criteo.com
criteo.net
taboola.com
outbrain.com
scorecardresearch.com
quantserve.com
moatads.com
pubmatic.com
rubiconproject.com
openx.net
casalemedia.com
amazon-adsystem.com
smartadserver.com
adform.net
bidswitch.net
mathtag.com
serving-sys.com
flashtalking.com
adroll.com
teads.tv
33across.com
sharethrough.com
contextweb.com
lijit.com
spotxchange.com
yieldmo.com
revcontent.com
mgid.com
popads.net
propellerads.com
exoclick.com
zedo.com
adcolony.com
applovin.com
chartboost.com
inmobi.com
startappservice.com
supersonicads.com
unityads.unity3d.com
an.facebook.com
bat.bing.com
analytics.tiktok.com
";

/// Liste de blocage courante et état du rafraîchissement.
pub struct AdBlock {
    path: PathBuf,
    list: Mutex<Option<Arc<Blocklist>>>,
    /// La liste chargée est la complète (et non celle de secours).
    full: AtomicBool,
    /// Un rafraîchissement est en cours.
    refreshing: AtomicBool,
}

/// Garde qui remet `refreshing` à faux, même en cas de panique.
pub struct RefreshGuard<'a>(&'a AtomicBool);

impl Drop for RefreshGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl AdBlock {
    pub fn new(path: PathBuf) -> Self {
        AdBlock {
            path,
            list: Mutex::new(None),
            full: AtomicBool::new(false),
            refreshing: AtomicBool::new(false),
        }
    }

    /// Liste actuellement utilisable.
    pub fn current(&self) -> Option<Arc<Blocklist>> {
        lock(&self.list).clone()
    }

    /// Garantit une liste immédiate : la liste de secours si rien n'est chargé.
    pub fn ensure_fallback(&self) {
        let mut list = lock(&self.list);
        if list.is_none() {
            *list = Some(Arc::new(Blocklist::parse(FALLBACK)));
            self.full.store(false, Ordering::Release);
        }
    }

    /// Libère la liste (bloqueur désactivé).
    pub fn release(&self) {
        *lock(&self.list) = None;
        self.full.store(false, Ordering::Release);
    }

    /// Réserve le rafraîchissement ; `None` s'il y en a déjà un en cours.
    pub fn begin_refresh(&self) -> Option<RefreshGuard<'_>> {
        (!self.refreshing.swap(true, Ordering::AcqRel)).then_some(RefreshGuard(&self.refreshing))
    }

    fn install(&self, list: Blocklist) {
        log::info!("liste de blocage : {} domaines", list.len());
        *lock(&self.list) = Some(Arc::new(list));
        self.full.store(true, Ordering::Release);
    }

    /// Âge du fichier local ; `None` s'il est absent.
    fn file_age(&self) -> Option<Duration> {
        let modified = fs::metadata(&self.path).and_then(|m| m.modified()).ok()?;
        Some(
            SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default(),
        )
    }

    fn load_file(&self) -> Option<Blocklist> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Some(Blocklist::parse(&text)).filter(|l| !l.is_empty()),
            Err(e) => {
                log::warn!("lecture de {} : {e}", self.path.display());
                None
            }
        }
    }

    /// Charge la liste locale, ou la télécharge si elle est absente ou trop vieille.
    /// Bloquant (réseau, disque, analyse) ; renvoie `true` si la liste a changé.
    pub fn refresh_blocking(&self) -> bool {
        let age = self.file_age();
        if age.is_some_and(|a| a < MAX_AGE) {
            if self.full.load(Ordering::Acquire) {
                return false;
            }
            if let Some(list) = self.load_file() {
                self.install(list);
                return true;
            }
        }
        log::info!("téléchargement de la liste de blocage");
        match download(URL, DOWNLOAD_TIMEOUT) {
            Ok(text) => {
                let list = Blocklist::parse(&text);
                if list.len() >= MIN_DOMAINS {
                    if let Err(e) = write_atomic(&self.path, text.as_bytes()) {
                        log::warn!("enregistrement de la liste de blocage : {e}");
                    }
                    self.install(list);
                    return true;
                }
                log::warn!(
                    "liste de blocage téléchargée invalide ({} domaines)",
                    list.len()
                );
            }
            Err(e) => log::warn!("téléchargement de la liste de blocage : {e}"),
        }
        // Échec : une liste locale, même ancienne, vaut mieux que celle de secours.
        if age.is_some() && !self.full.load(Ordering::Acquire) {
            if let Some(list) = self.load_file() {
                self.install(list);
                return true;
            }
        }
        false
    }
}

/// Télécharge un texte par `Windows.Web.Http.HttpClient` (proxy du système respecté).
fn download(url: &str, timeout: Duration) -> Result<String, String> {
    use windows::{core::HSTRING, Foundation::Uri, Web::Http::HttpClient};
    use windows_future::AsyncStatus;

    let err =
        |e: windows::core::Error| format!("erreur Windows 0x{:08X} ({})", e.code().0, e.message());
    let client = HttpClient::new().map_err(err)?;
    let uri = Uri::CreateUri(&HSTRING::from(url)).map_err(err)?;
    let op = client.GetStringAsync(&uri).map_err(err)?;
    let start = Instant::now();
    while op.Status().map_err(err)? == AsyncStatus::Started {
        if start.elapsed() > timeout {
            if let Err(e) = op.Cancel() {
                log::debug!("annulation du téléchargement : {e}");
            }
            return Err("délai dépassé".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let text = op.GetResults().map_err(err)?;
    Ok(text.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accès réseau : `cargo test -p partage-wifi -- --ignored telechargement`.
    #[test]
    #[ignore = "accès réseau"]
    fn telechargement_reel() {
        let text = download(URL, DOWNLOAD_TIMEOUT).unwrap();
        let list = Blocklist::parse(&text);
        assert!(list.len() >= MIN_DOMAINS, "{} domaines", list.len());
        assert!(list.contains("doubleclick.net"));
    }

    #[test]
    fn liste_de_secours() {
        let list = Blocklist::parse(FALLBACK);
        assert!(list.len() >= 40, "{} domaines", list.len());
        assert!(list.contains("securepubads.g.doubleclick.net"));
        assert!(list.contains("pagead2.googlesyndication.com"));
        assert!(!list.contains("google.com"));
        assert!(!list.contains("facebook.com"));
    }

    #[test]
    fn secours_puis_liberation() {
        let ab = AdBlock::new(std::env::temp_dir().join("axios-test-inexistant.txt"));
        assert!(ab.current().is_none());
        ab.ensure_fallback();
        let first = ab.current().unwrap();
        ab.ensure_fallback();
        assert!(
            Arc::ptr_eq(&first, &ab.current().unwrap()),
            "pas d'analyse en double"
        );
        ab.release();
        assert!(ab.current().is_none());
    }

    #[test]
    fn un_seul_rafraichissement_a_la_fois() {
        let ab = AdBlock::new(PathBuf::new());
        let guard = ab.begin_refresh();
        assert!(guard.is_some());
        assert!(ab.begin_refresh().is_none());
        drop(guard);
        assert!(ab.begin_refresh().is_some());
    }

    #[test]
    fn fichier_local_recent_charge_sans_reseau() {
        let path = std::env::temp_dir().join(format!("axios-test-bl-{}.txt", std::process::id()));
        let text: String = (0..10)
            .map(|i| format!("0.0.0.0 ads{i}.example.com\n"))
            .collect();
        write_atomic(&path, text.as_bytes()).unwrap();
        let ab = AdBlock::new(path.clone());
        ab.ensure_fallback();
        assert!(ab.refresh_blocking());
        assert_eq!(ab.current().unwrap().len(), 10);
        assert!(!ab.refresh_blocking(), "déjà chargée");
        let _ = fs::remove_file(&path);
    }
}
