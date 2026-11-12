//! Surveillance du point d'accès natif : le moteur tourne exactement quand il est allumé.
//!
//! La logique est indépendante du système ([`Host`]) pour être testée sans Windows réel.

use std::{
    net::Ipv4Addr,
    path::PathBuf,
    time::{Duration, Instant},
};

use pw_engine::{Engine, EngineConfig, EngineStats};
use pw_support::{activity, windivert, ENGINE_LOCK, PREFIX_LEN, TCP_PORT};
use pw_winsys::{
    hotspot, net,
    sync::{NamedEvent, NamedLock},
    WinsysError,
};

/// Intervalle de sondage du point d'accès.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Accès au système dont le moniteur a besoin.
pub trait Host {
    type Engine: RunningEngine;
    /// État du point d'accès ; une erreur signifie « inconnu » (l'état courant est conservé).
    fn hotspot_on(&mut self) -> Result<bool, String>;
    /// Index de l'interface du point d'accès, s'il est déjà monté.
    fn hotspot_interface(&mut self) -> Option<u32>;
    /// Démarre le moteur ; `Ok(None)` s'il est déjà utilisé par un autre processus.
    fn start_engine(&mut self) -> Result<Option<Self::Engine>, String>;
}

/// Moteur en marche, vu par le moniteur.
pub trait RunningEngine {
    fn set_interface(&self, if_index: Option<u32>);
    fn stats(&self) -> EngineStats;
    fn shutdown(self);
}

pub struct Monitor<H: Host> {
    host: H,
    engine: Option<H::Engine>,
    if_index: Option<u32>,
    /// Dernière erreur consignée : une erreur qui se répète n'est écrite qu'une fois.
    last_error: Option<String>,
    /// Le moteur est tenu par l'application Partage Wi-Fi (déjà consigné).
    busy: bool,
}

impl<H: Host> Monitor<H> {
    pub fn new(host: H) -> Self {
        Monitor {
            host,
            engine: None,
            if_index: None,
            last_error: None,
            busy: false,
        }
    }

    /// `true` si le moteur tourne.
    pub fn is_running(&self) -> bool {
        self.engine.is_some()
    }

    /// Interface transmise au moteur.
    pub fn interface(&self) -> Option<u32> {
        self.if_index
    }

    /// Un pas de surveillance : aligne le moteur sur l'état du point d'accès.
    pub fn tick(&mut self) {
        match self.host.hotspot_on() {
            Ok(true) => self.ensure_running(),
            Ok(false) => self.stop(),
            Err(e) => self.report(format!("état du point d'accès : {e}")),
        }
    }

    fn ensure_running(&mut self) {
        if self.engine.is_none() {
            match self.host.start_engine() {
                Ok(Some(engine)) => {
                    log::info!("point d'accès allumé : moteur démarré");
                    self.engine = Some(engine);
                    self.if_index = None;
                    self.busy = false;
                    self.last_error = None;
                }
                Ok(None) => {
                    if !self.busy {
                        log::info!("moteur utilisé par l'application Partage Wi-Fi : en attente");
                        self.busy = true;
                    }
                    return;
                }
                Err(e) => {
                    self.report(e);
                    return;
                }
            }
        }
        // L'interface apparaît quelques secondes après l'allumage et change à chaque redémarrage
        // du point d'accès (changement de bande, par exemple) : on la suit à chaque pas.
        let if_index = self.host.hotspot_interface();
        if if_index != self.if_index {
            if let Some(engine) = &self.engine {
                engine.set_interface(if_index);
            }
            self.if_index = if_index;
        }
    }

    /// Arrête le moteur s'il tourne.
    pub fn stop(&mut self) {
        self.busy = false;
        if let Some(engine) = self.engine.take() {
            engine.shutdown();
            self.if_index = None;
            log::info!("point d'accès éteint : moteur arrêté");
        }
    }

    fn report(&mut self, message: String) {
        if self.last_error.as_deref() != Some(message.as_str()) {
            log::error!("{message}");
            self.last_error = Some(message);
        }
    }

    /// Boucle jusqu'au signal d'arrêt, puis arrête le moteur.
    pub fn run(mut self, stop: &NamedEvent) {
        let period = Duration::from_secs(activity::PERIOD_SECS);
        let mut last_report = Instant::now();
        let mut last_packets = 0;
        loop {
            self.tick();
            if last_report.elapsed() >= period {
                last_report = Instant::now();
                if let Some(engine) = &self.engine {
                    last_packets = activity::log_if_changed(&engine.stats(), last_packets);
                }
            }
            if stop.wait(POLL_INTERVAL) {
                log::info!("signal d'arrêt reçu");
                break;
            }
        }
        self.stop();
    }
}

/// Le vrai système : point d'accès WinRT, table IP, moteur WinDivert.
pub struct System {
    gateway: Ipv4Addr,
    dll: Option<PathBuf>,
}

impl System {
    pub fn new(gateway: Ipv4Addr) -> Self {
        System { gateway, dll: None }
    }

    /// Chemin de `WinDivert.dll`, extrait au premier besoin.
    fn dll(&mut self) -> Result<PathBuf, String> {
        if let Some(path) = &self.dll {
            return Ok(path.clone());
        }
        let path =
            windivert::ensure_extracted().map_err(|e| format!("extraction de WinDivert : {e}"))?;
        Ok(self.dll.insert(path).clone())
    }
}

impl Host for System {
    type Engine = Running;

    fn hotspot_on(&mut self) -> Result<bool, String> {
        match hotspot::info() {
            Ok(info) => Ok(info.on),
            // Sans connexion internet, le point d'accès ne peut pas être allumé.
            Err(WinsysError::NoInternet) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    fn hotspot_interface(&mut self) -> Option<u32> {
        net::interface_index_for(self.gateway)
    }

    fn start_engine(&mut self) -> Result<Option<Running>, String> {
        let Some(lock) = NamedLock::try_acquire(ENGINE_LOCK).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let cfg = EngineConfig {
            gateway: self.gateway,
            prefix_len: PREFIX_LEN,
            tcp_port: TCP_PORT,
            windivert_dll: self.dll()?,
        };
        let engine = Engine::start(cfg).map_err(|e| format!("démarrage du moteur : {e}"))?;
        Ok(Some(Running {
            engine,
            _lock: lock,
        }))
    }
}

/// Moteur réel et verrou d'exclusivité, libéré après l'arrêt du moteur.
pub struct Running {
    engine: Engine,
    _lock: NamedLock,
}

impl RunningEngine for Running {
    fn set_interface(&self, if_index: Option<u32>) {
        self.engine.set_hotspot_interface(if_index);
    }

    fn stats(&self) -> EngineStats {
        self.engine.stats()
    }

    fn shutdown(self) {
        self.engine.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    /// Journal des actions du faux moteur.
    type Calls = Rc<RefCell<Vec<String>>>;

    struct FakeEngine(Calls);

    impl RunningEngine for FakeEngine {
        fn set_interface(&self, if_index: Option<u32>) {
            self.0.borrow_mut().push(format!("interface {if_index:?}"));
        }
        fn stats(&self) -> EngineStats {
            EngineStats::default()
        }
        fn shutdown(self) {
            self.0.borrow_mut().push("arrêt".into());
        }
    }

    struct FakeHost {
        on: Result<bool, String>,
        interface: Option<u32>,
        busy: bool,
        fail_start: bool,
        starts: u32,
        calls: Calls,
    }

    impl FakeHost {
        fn new() -> Self {
            FakeHost {
                on: Ok(false),
                interface: None,
                busy: false,
                fail_start: false,
                starts: 0,
                calls: Calls::default(),
            }
        }
    }

    impl Host for FakeHost {
        type Engine = FakeEngine;
        fn hotspot_on(&mut self) -> Result<bool, String> {
            self.on.clone()
        }
        fn hotspot_interface(&mut self) -> Option<u32> {
            self.interface
        }
        fn start_engine(&mut self) -> Result<Option<FakeEngine>, String> {
            self.starts += 1;
            if self.fail_start {
                return Err("échec".into());
            }
            Ok((!self.busy).then(|| FakeEngine(Rc::clone(&self.calls))))
        }
    }

    fn calls(m: &Monitor<FakeHost>) -> Vec<String> {
        m.host.calls.borrow().clone()
    }

    #[test]
    fn eteint_ne_demarre_rien() {
        let mut m = Monitor::new(FakeHost::new());
        m.tick();
        assert!(!m.is_running());
        assert_eq!(m.host.starts, 0);
    }

    #[test]
    fn suit_l_allumage_l_interface_puis_l_extinction() {
        let mut m = Monitor::new(FakeHost::new());
        m.host.on = Ok(true);
        m.tick();
        assert!(m.is_running());
        assert_eq!(m.interface(), None, "interface pas encore montée");

        m.host.interface = Some(10);
        m.tick();
        m.tick();
        assert_eq!(m.interface(), Some(10));

        // Redémarrage du point d'accès : nouvelle interface.
        m.host.interface = Some(12);
        m.tick();

        m.host.on = Ok(false);
        m.tick();
        assert!(!m.is_running());
        assert_eq!(m.interface(), None);
        assert_eq!(m.host.starts, 1);
        assert_eq!(
            calls(&m),
            ["interface Some(10)", "interface Some(12)", "arrêt"]
        );
    }

    #[test]
    fn etat_inconnu_conserve_le_moteur() {
        let mut m = Monitor::new(FakeHost::new());
        m.host.on = Ok(true);
        m.tick();
        m.host.on = Err("WinRT indisponible".into());
        m.tick();
        assert!(m.is_running());
        assert!(calls(&m).is_empty());
    }

    #[test]
    fn moteur_occupe_reessaye_sans_demarrer() {
        let mut m = Monitor::new(FakeHost::new());
        m.host.on = Ok(true);
        m.host.busy = true;
        m.tick();
        m.tick();
        assert!(!m.is_running());
        assert_eq!(m.host.starts, 2);

        // L'application est fermée : le moteur est repris.
        m.host.busy = false;
        m.tick();
        assert!(m.is_running());
    }

    #[test]
    fn echec_de_demarrage_retente_au_pas_suivant() {
        let mut m = Monitor::new(FakeHost::new());
        m.host.on = Ok(true);
        m.host.fail_start = true;
        m.tick();
        assert!(!m.is_running());
        m.host.fail_start = false;
        m.tick();
        assert!(m.is_running());
    }

    #[test]
    fn stop_arrete_le_moteur() {
        let mut m = Monitor::new(FakeHost::new());
        m.host.on = Ok(true);
        m.tick();
        m.stop();
        assert!(!m.is_running());
        assert_eq!(calls(&m), ["arrêt"]);
    }
}
