//! État partagé de l'application : moteur, point d'accès, réglages, instantané publié à
//! l'interface.
//!
//! Toutes les transitions du partage (démarrage, arrêt, reconfiguration, choix de la
//! connexion, adoption d'un changement externe, arrêt de l'application) sont sérialisées par
//! un verrou asynchrone `op` : aucune course n'est possible entre un clic, le sondage et la
//! fermeture. Les modifications de réglages ont leur propre verrou (`settings_op`). Les
//! verrous `std` protégeant l'état ne sont jamais tenus à travers un `.await`.

use std::{
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use pw_engine::{Engine, EngineConfig, EngineStats};
use pw_support::{paths, subnet_cidr, windivert, ENGINE_LOCK, PREFIX_LEN, TCP_PORT};
use pw_winsys::{
    autostart, firewall,
    hotspot::{self, Band, HotspotInfo, Source},
    net,
    sync::NamedLock,
    WinsysError,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;
use tokio::time::{interval, timeout, MissedTickBehavior};

use crate::{
    blocklist::AdBlock,
    clock,
    devices::{display_name, guess_kind, normalize_id, vendor_label, DeviceKind, DeviceStore},
    error::{blocking, blocking_try, AppError},
    history::{History, Range, Slot, Usage},
    policy::{build_policy, Peer},
    settings::{validate_limit, Settings, SettingsFile, SettingsPatch},
    store::{lock, JsonFile},
    tray,
};

pub const FIREWALL_RULE: &str = "PartageWiFi";
pub const TASK_NAME: &str = "PartageWiFi";

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const IFACE_RETRY_DELAY: Duration = Duration::from_millis(500);
const IFACE_ATTEMPTS_START: u32 = 20; // ~10 s
const IFACE_ATTEMPTS_ADOPT: u32 = 6; // ~3 s
const SHUTDOWN_STEP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Off,
    Starting,
    On,
    Stopping,
    Error,
}

/// Instantané publié à l'interface (forme `Snapshot` de `types.ts`).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub status: Status,
    pub ssid: String,
    pub passphrase: String,
    pub band: Band,
    pub max_clients: u32,
    pub supported_bands: Vec<Band>,
    /// Connexion internet partagée.
    pub source: Option<Source>,
    /// Horodatage (ms) du passage à `On`, `None` à l'arrêt.
    pub started_at: Option<i64>,
    pub error: Option<String>,
    pub engine_ready: bool,
}

struct State {
    snapshot: Snapshot,
    if_index: Option<u32>,
    /// Erreur d'une opération de partage (prioritaire à l'affichage).
    op_error: Option<String>,
    /// Erreur de chargement du moteur.
    engine_error: Option<String>,
    /// Le point d'accès s'est éteint faute de connexion alors que le partage était actif :
    /// à rallumer au retour de la connexion (réglage `autoRestart`).
    restart_pending: bool,
}

pub struct Controller {
    app: AppHandle,
    gateway: Ipv4Addr,
    state: Mutex<State>,
    engine: Mutex<Option<Engine>>,
    /// Exclusivité du moteur vis-à-vis du partage automatique ; tenu tant que le moteur tourne.
    engine_lock: Mutex<Option<NamedLock>>,
    dll: OnceLock<PathBuf>,
    /// Sérialise les transitions ; tenu à travers des `.await`, d'où un verrou tokio.
    op: tokio::sync::Mutex<()>,
    /// Sérialise les modifications de réglages.
    settings_op: tokio::sync::Mutex<()>,
    settings: JsonFile<SettingsFile>,
    /// `settings.json` absent au lancement : réglages à initialiser depuis le système.
    settings_missing: bool,
    devices: JsonFile<DeviceStore>,
    history: JsonFile<History>,
    adblock: Arc<AdBlock>,
    /// Appareils présents (correspondance IP ↔ MAC) ayant servi à la dernière politique.
    peers: Mutex<Vec<Peer>>,
}

impl Controller {
    pub fn new(app: AppHandle) -> Arc<Self> {
        let gateway = net::ics_gateway();
        log::info!("passerelle ICS : {gateway}");
        let dir = paths::app_dir();
        let (settings, settings_found) =
            JsonFile::load_or(dir.join("settings.json"), SettingsFile::default);
        let (devices, _) = JsonFile::load_or(dir.join("devices.json"), DeviceStore::default);
        let (history, _) = JsonFile::load_or(dir.join("history.json"), History::default);
        Arc::new(Controller {
            app,
            gateway,
            state: Mutex::new(State {
                snapshot: Snapshot {
                    status: Status::Off,
                    ssid: String::new(),
                    passphrase: String::new(),
                    band: Band::Auto,
                    max_clients: 0,
                    supported_bands: vec![Band::Auto],
                    source: None,
                    started_at: None,
                    error: None,
                    engine_ready: false,
                },
                if_index: None,
                op_error: None,
                engine_error: None,
                restart_pending: false,
            }),
            engine: Mutex::new(None),
            engine_lock: Mutex::new(None),
            dll: OnceLock::new(),
            op: tokio::sync::Mutex::new(()),
            settings_op: tokio::sync::Mutex::new(()),
            settings,
            settings_missing: !settings_found,
            devices,
            history,
            adblock: Arc::new(AdBlock::new(dir.join("blocklist.txt"))),
            peers: Mutex::new(Vec::new()),
        })
    }

    pub fn app(&self) -> &AppHandle {
        &self.app
    }

    pub fn snapshot(&self) -> Snapshot {
        lock(&self.state).snapshot.clone()
    }

    pub fn if_index(&self) -> Option<u32> {
        lock(&self.state).if_index
    }

    /// Compteurs du moteur (valeurs par défaut s'il n'est pas chargé).
    pub fn engine_stats(&self) -> EngineStats {
        lock(&self.engine)
            .as_ref()
            .map(Engine::stats)
            .unwrap_or_default()
    }

    pub fn settings(&self) -> Settings {
        self.settings.read(|f| f.settings.clone())
    }

    /// Copie des préférences d'appareils.
    pub fn device_prefs(&self) -> DeviceStore {
        self.devices.read(Clone::clone)
    }

    /// Modifie l'état, recalcule le message d'erreur et l'heure de démarrage, puis publie si
    /// l'instantané a changé.
    fn update(&self, f: impl FnOnce(&mut State)) {
        let published = {
            let mut st = lock(&self.state);
            let before = st.snapshot.clone();
            f(&mut st);
            st.snapshot.error = st.op_error.clone().or_else(|| st.engine_error.clone());
            match st.snapshot.status {
                Status::On if st.snapshot.started_at.is_none() => {
                    st.snapshot.started_at = Some(clock::now_ms());
                }
                // Nouveau démarrage ou arrêt : l'heure précédente ne vaut plus.
                Status::Off | Status::Starting => st.snapshot.started_at = None,
                _ => {}
            }
            (st.snapshot != before).then(|| st.snapshot.clone())
        };
        if let Some(snapshot) = published {
            tray::refresh(&self.app, &snapshot);
            if let Err(e) = self.app.emit("snapshot", &snapshot) {
                log::warn!("émission de « snapshot » impossible : {e}");
            }
        }
    }

    fn set_status(&self, status: Status) {
        self.update(|st| st.snapshot.status = status);
    }

    fn fail(&self, message: String) {
        self.update(|st| {
            st.op_error = Some(message);
            st.snapshot.status = Status::Error;
        });
    }

    fn apply_config(&self, info: &HotspotInfo) {
        self.update(|st| {
            st.snapshot.ssid.clone_from(&info.ssid);
            st.snapshot.passphrase.clone_from(&info.passphrase);
            st.snapshot.band = info.band;
            st.snapshot.max_clients = info.max_clients;
            st.snapshot
                .supported_bands
                .clone_from(&info.supported_bands);
        });
    }

    /// Relit la connexion partagée et la publie si elle a changé.
    async fn refresh_source(&self) {
        match blocking_try(hotspot::current_source).await {
            Ok(source) => self.update(|st| st.snapshot.source = source),
            Err(e) => log::debug!("connexion partagée : {e}"),
        }
    }

    fn set_engine_interface(&self, if_index: Option<u32>) {
        if let Some(engine) = lock(&self.engine).as_ref() {
            engine.set_hotspot_interface(if_index);
        }
    }

    fn attach(&self, if_index: u32) {
        log::info!("interface du point d'accès : {if_index}");
        self.update(|st| st.if_index = Some(if_index));
        self.set_engine_interface(Some(if_index));
    }

    fn detach(&self) {
        self.update(|st| st.if_index = None);
        self.set_engine_interface(None);
    }

    /// Résout l'index d'interface du réseau ICS, avec retentatives (l'interface
    /// apparaît quelques secondes après le démarrage du point d'accès).
    async fn resolve_interface(&self, attempts: u32) -> Result<u32, AppError> {
        let gateway = self.gateway;
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(IFACE_RETRY_DELAY).await;
            }
            if let Some(idx) = blocking(move || net::interface_index_for(gateway)).await? {
                return Ok(idx);
            }
        }
        Err(AppError::InterfaceNotFound)
    }

    /// Après un redémarrage du point d'accès par Windows (reconfiguration, changement de
    /// connexion), l'interface peut avoir été recréée : on la résout à nouveau.
    async fn reattach(&self, info: &HotspotInfo) {
        if !(info.on && self.snapshot().status == Status::On) {
            return;
        }
        match self.resolve_interface(IFACE_ATTEMPTS_START).await {
            Ok(idx) => self.attach(idx),
            Err(e) => {
                log::error!("après redémarrage du point d'accès : {e}");
                self.detach();
                self.fail(e.to_string());
            }
        }
    }

    /// Extrait WinDivert (une seule fois) et renvoie le chemin de la DLL.
    async fn prepare_dll(&self) -> Result<PathBuf, AppError> {
        if let Some(path) = self.dll.get() {
            return Ok(path.clone());
        }
        let path = blocking_try(windivert::ensure_extracted).await?;
        Ok(self.dll.get_or_init(|| path).clone())
    }

    /// Démarre le moteur s'il ne tourne pas ; met à jour `engineReady`.
    async fn ensure_engine(&self) {
        if lock(&self.engine).is_some() {
            return;
        }
        let result = async {
            let engine_lock = blocking_try(|| NamedLock::try_acquire(ENGINE_LOCK))
                .await?
                .ok_or(AppError::EngineBusy)?;
            let windivert_dll = self.prepare_dll().await?;
            let cfg = EngineConfig {
                gateway: self.gateway,
                prefix_len: PREFIX_LEN,
                tcp_port: TCP_PORT,
                windivert_dll,
            };
            let engine = blocking_try(move || Engine::start(cfg)).await?;
            Ok::<_, AppError>((engine, engine_lock))
        }
        .await;
        match result {
            Ok((engine, engine_lock)) => {
                log::info!("moteur démarré");
                if let Some(idx) = self.if_index() {
                    engine.set_hotspot_interface(Some(idx));
                }
                *lock(&self.engine) = Some(engine);
                *lock(&self.engine_lock) = Some(engine_lock);
                self.apply_policy();
                self.update(|st| {
                    st.snapshot.engine_ready = true;
                    st.engine_error = None;
                });
            }
            Err(e) => {
                log::error!("moteur indisponible : {e}");
                self.update(|st| {
                    st.snapshot.engine_ready = false;
                    st.engine_error = Some(e.to_string());
                });
            }
        }
    }

    /// Reconstruit la politique complète du moteur (réglages, appareils, voisins) et
    /// l'applique. Peu coûteux : la liste de blocage est partagée, pas recopiée.
    pub fn apply_policy(&self) {
        let settings = self.settings();
        let peers = lock(&self.peers).clone();
        let blocklist = settings.ad_block.then(|| self.adblock.current()).flatten();
        let policy = self
            .devices
            .read(|devices| build_policy(&settings, devices, &peers, blocklist));
        if let Some(engine) = lock(&self.engine).as_ref() {
            engine.set_policy(policy);
        }
    }

    /// Nouvelle correspondance des appareils présents : la politique est reconstruite si elle
    /// a changé (les blocages et limites sont indexés par IP).
    pub fn set_peers(&self, mut peers: Vec<Peer>) {
        peers.sort();
        peers.dedup_by_key(|p| p.ip);
        {
            let mut current = lock(&self.peers);
            if *current == peers {
                return;
            }
            *current = peers;
        }
        self.apply_policy();
    }

    /// Initialisation : extraction WinDivert, pare-feu, moteur, réglages, état du point
    /// d'accès. Aucune erreur n'est fatale : l'interface doit pouvoir s'ouvrir.
    pub async fn init(self: &Arc<Self>) {
        let _op = self.op.lock().await;

        if let Err(e) = self.prepare_dll().await {
            log::error!("extraction de WinDivert : {e}");
        }

        match std::env::current_exe() {
            Ok(exe) => {
                let remote = self.remote();
                let result = blocking_try(move || {
                    firewall::ensure_rule(FIREWALL_RULE, &exe, TCP_PORT, &remote)
                })
                .await;
                match result {
                    Ok(()) => log::info!("règle de pare-feu en place"),
                    Err(e) => log::error!("règle de pare-feu : {e}"),
                }
            }
            Err(e) => log::error!("chemin de l'exécutable introuvable : {e}"),
        }

        self.init_settings().await;
        self.ensure_engine().await;

        match blocking_try(hotspot::info).await {
            Ok(info) => self.sync_with(info, IFACE_ATTEMPTS_ADOPT).await,
            Err(e) => log::warn!("état initial du point d'accès : {e}"),
        }
        self.refresh_source().await;
    }

    /// CIDR du réseau du point d'accès.
    fn remote(&self) -> String {
        subnet_cidr(self.gateway, PREFIX_LEN)
    }

    /// Applique les réglages enregistrés au système (premier lancement : reprend l'état de la
    /// tâche planifiée de la version précédente).
    async fn init_settings(self: &Arc<Self>) {
        let task_enabled = blocking(|| autostart::is_enabled(TASK_NAME))
            .await
            .unwrap_or(false);
        if self.settings_missing {
            // Version précédente : démarrer avec Windows impliquait de partager.
            self.settings.modify(|f| {
                f.settings.autostart = task_enabled;
                f.settings.share_on_launch = task_enabled;
            });
            self.settings.save().await;
        }
        let file = self.settings.read(Clone::clone);
        let s = &file.settings;

        if let Some(id) = file.source_id.clone() {
            if let Err(e) = blocking_try(move || hotspot::select_source(Some(&id))).await {
                log::warn!("connexion partagée enregistrée : {e}");
            }
        }
        if s.autostart != task_enabled {
            if let Err(e) = self.apply_autostart(s.autostart).await {
                log::warn!("démarrage avec Windows : {e}");
            }
        }
        self.apply_keep_alive(s.keep_alive).await;
        if let Err(e) = self.apply_isolation(s.isolate).await {
            log::error!("isolation des appareils : {e}");
        }
        if s.ad_block {
            self.adblock.ensure_fallback();
            self.refresh_blocklist();
        }
    }

    async fn apply_autostart(&self, enabled: bool) -> Result<(), AppError> {
        let exe = std::env::current_exe()?;
        blocking_try(move || autostart::set(TASK_NAME, enabled, &exe, "--minimized")).await
    }

    async fn apply_keep_alive(&self, enabled: bool) {
        if let Err(e) = blocking_try(move || hotspot::set_keep_alive(enabled)).await {
            log::warn!("maintien du point d'accès : {e}");
        }
    }

    async fn apply_isolation(&self, enabled: bool) -> Result<(), AppError> {
        let remote = self.remote();
        blocking_try(move || firewall::set_isolation(enabled, &remote, TCP_PORT)).await
    }

    /// Charge ou télécharge la liste de blocage complète en tâche de fond, puis met à jour la
    /// politique. Sans effet si un rafraîchissement est déjà en cours.
    pub fn refresh_blocklist(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let adblock = Arc::clone(&this.adblock);
            let changed = blocking(move || {
                let Some(_guard) = adblock.begin_refresh() else {
                    return false;
                };
                adblock.refresh_blocking()
            })
            .await
            .unwrap_or(false);
            if changed {
                this.apply_policy();
            }
        });
    }

    /// Aligne l'état sur celui, observé, du point d'accès (verrou `op` tenu par l'appelant).
    async fn sync_with(&self, info: HotspotInfo, attempts: u32) {
        self.apply_config(&info);
        match (info.on, self.snapshot().status) {
            (true, Status::Off | Status::Error) => {
                log::info!("point d'accès actif (changement externe)");
                match self.resolve_interface(attempts).await {
                    Ok(idx) => {
                        self.attach(idx);
                        self.update(|st| {
                            st.op_error = None;
                            st.restart_pending = false;
                            st.snapshot.status = Status::On;
                        });
                    }
                    Err(e) => log::warn!("adoption du point d'accès : {e}"),
                }
            }
            (false, Status::On) => {
                log::info!("point d'accès arrêté (changement externe)");
                self.detach();
                self.set_status(Status::Off);
            }
            (true, Status::On) => self.update(|st| st.restart_pending = false),
            _ => {}
        }
    }

    /// Relance automatique : la connexion est revenue (le point d'accès répond) après une
    /// coupure qui l'avait éteint (verrou `op` tenu par l'appelant).
    async fn auto_restart(&self) {
        let pending = {
            let st = lock(&self.state);
            st.restart_pending && matches!(st.snapshot.status, Status::Off | Status::Error)
        };
        if !pending {
            return;
        }
        self.update(|st| st.restart_pending = false);
        if self.settings().auto_restart {
            log::info!("connexion revenue : relance du point d'accès");
            self.start_sharing().await;
        }
    }

    /// Active ou désactive le partage. Un échec est consigné dans l'instantané
    /// (`status = error`) plutôt que renvoyé comme erreur de commande.
    pub async fn set_sharing(&self, on: bool) -> Snapshot {
        let _op = self.op.lock().await;
        self.update(|st| st.restart_pending = false);
        if on {
            self.start_sharing().await;
        } else {
            self.stop_sharing().await;
        }
        self.snapshot()
    }

    async fn start_sharing(&self) {
        if self.snapshot().status == Status::On {
            return;
        }
        self.update(|st| {
            st.op_error = None;
            st.snapshot.status = Status::Starting;
        });
        match self.do_start().await {
            Ok(()) => self.set_status(Status::On),
            Err(e) => {
                log::error!("démarrage du partage : {e}");
                self.fail(e.to_string());
            }
        }
        self.refresh_source().await;
    }

    async fn do_start(&self) -> Result<(), AppError> {
        // Moteur absent (échec au lancement) : nouvelle tentative, sans bloquer le partage.
        self.ensure_engine().await;
        let info = blocking_try(hotspot::start).await?;
        self.apply_config(&info);
        match self.resolve_interface(IFACE_ATTEMPTS_START).await {
            Ok(idx) => {
                self.attach(idx);
                Ok(())
            }
            Err(e) => {
                // Sans interface rien ne serait relayé : on ne laisse pas le point d'accès actif.
                if let Err(stop_err) = blocking_try(hotspot::stop).await {
                    log::warn!("arrêt après échec : {stop_err}");
                }
                Err(e)
            }
        }
    }

    async fn stop_sharing(&self) {
        if self.snapshot().status == Status::Off {
            return;
        }
        self.update(|st| {
            st.op_error = None;
            st.snapshot.status = Status::Stopping;
        });
        self.detach();
        match blocking_try(hotspot::stop).await {
            Ok(info) => {
                self.apply_config(&info);
                self.set_status(Status::Off);
            }
            Err(e) => {
                log::error!("arrêt du partage : {e}");
                self.fail(e.to_string());
            }
        }
    }

    /// Applique un nouveau réseau (le point d'accès redémarre s'il est actif).
    pub async fn configure(
        &self,
        ssid: String,
        passphrase: String,
        band: Band,
    ) -> Result<Snapshot, AppError> {
        let _op = self.op.lock().await;
        let info = blocking_try(move || hotspot::configure(&ssid, &passphrase, Some(band))).await?;
        self.apply_config(&info);
        self.reattach(&info).await;
        Ok(self.snapshot())
    }

    /// Connexions internet disponibles.
    pub async fn sources(&self) -> Result<Vec<Source>, AppError> {
        blocking_try(hotspot::sources).await
    }

    /// Choisit la connexion partagée (mémorisée) ; le point d'accès redémarre s'il est actif.
    pub async fn set_source(&self, id: String) -> Result<Snapshot, AppError> {
        let _op = self.op.lock().await;
        let choice = Some(id.trim().to_owned()).filter(|s| !s.is_empty());
        let selected = choice.clone();
        let info = blocking_try(move || hotspot::select_source(selected.as_deref())).await?;
        self.settings.modify(|f| f.source_id = choice);
        self.settings.save().await;
        self.apply_config(&info);
        self.reattach(&info).await;
        self.refresh_source().await;
        Ok(self.snapshot())
    }

    /// Modifie des réglages et les applique. Un effet système refusé (tâche planifiée,
    /// pare-feu) laisse le réglage concerné inchangé et renvoie l'erreur.
    pub async fn update_settings(
        self: &Arc<Self>,
        patch: SettingsPatch,
    ) -> Result<Settings, AppError> {
        let _guard = self.settings_op.lock().await;
        let old = self.settings();
        let mut new = old.patched(patch).map_err(AppError::Invalid)?;
        let mut failure = None;

        if new.autostart != old.autostart {
            if let Err(e) = self.apply_autostart(new.autostart).await {
                log::error!("démarrage avec Windows : {e}");
                new.autostart = old.autostart;
                failure = failure.or(Some(e));
            }
        }
        if new.isolate != old.isolate {
            if let Err(e) = self.apply_isolation(new.isolate).await {
                log::error!("isolation des appareils : {e}");
                new.isolate = old.isolate;
                failure = failure.or(Some(e));
            }
        }
        if new.keep_alive != old.keep_alive {
            self.apply_keep_alive(new.keep_alive).await;
        }
        if !new.auto_restart {
            self.update(|st| st.restart_pending = false);
        }

        self.settings.modify(|f| f.settings = new.clone());
        self.settings.save().await;

        match (old.ad_block, new.ad_block) {
            (false, true) => {
                self.adblock.ensure_fallback();
                self.refresh_blocklist();
            }
            (true, false) => self.adblock.release(),
            _ => {}
        }
        self.apply_policy();

        match failure {
            Some(e) => Err(e),
            None => Ok(new),
        }
    }

    /// Modifie les préférences de l'appareil `id`, les enregistre et met à jour la politique.
    async fn edit_device(
        &self,
        id: &str,
        f: impl FnOnce(&mut DeviceStore, &str) -> bool,
    ) -> Result<(), AppError> {
        let id = normalize_id(id);
        if id.is_empty() {
            return Err(AppError::Invalid("Appareil introuvable".into()));
        }
        if self.devices.modify(|d| f(d, &id)) {
            self.devices.save().await;
            self.apply_policy();
        }
        Ok(())
    }

    pub async fn rename_device(&self, id: &str, alias: &str) -> Result<(), AppError> {
        self.edit_device(id, |d, id| d.set_alias(id, alias)).await
    }

    pub async fn set_device_blocked(&self, id: &str, blocked: bool) -> Result<(), AppError> {
        self.edit_device(id, |d, id| d.set_blocked(id, blocked))
            .await
    }

    pub async fn set_device_limit(&self, id: &str, limit: Option<f64>) -> Result<(), AppError> {
        let limit = validate_limit(limit).map_err(AppError::Invalid)?;
        self.edit_device(id, |d, id| d.set_limit(id, limit)).await
    }

    /// Mémorise les noms d'hôte vus (pour nommer les appareils absents dans l'historique).
    pub async fn remember_hostnames(&self, names: &[(String, String)]) {
        let changed = self.devices.modify(|d| {
            names
                .iter()
                .fold(false, |acc, (id, name)| d.remember_hostname(id, name) | acc)
        });
        if changed {
            self.devices.save().await;
        }
    }

    /// Ajoute une minute de trafic à l'historique.
    pub async fn record_usage(&self, slot: Slot) {
        let (now, offset) = (clock::now_ms(), clock::local_offset_ms());
        self.history.modify(|h| h.record(now, offset, &slot));
        if !slot.is_empty() {
            self.history.save().await;
        }
    }

    /// Consommation agrégée sur la période, appareils nommés selon leurs préférences.
    pub fn usage(&self, range: Range) -> Usage {
        let prefs = self.device_prefs();
        let describe = |id: &str| -> (String, DeviceKind) {
            let entry = prefs.get(id);
            let alias = entry.map_or("", |e| e.alias.as_str());
            let hostname = entry.map_or("", |e| e.hostname.as_str());
            let mac = id.parse::<Ipv4Addr>().is_err().then_some(id);
            let vendor = vendor_label(mac);
            let kind = match guess_kind(hostname) {
                DeviceKind::Other => guess_kind(alias),
                kind => kind,
            };
            (display_name(id, alias, hostname, &vendor), kind)
        };
        let (now, offset) = (clock::now_ms(), clock::local_offset_ms());
        self.history.read(|h| h.usage(range, now, offset, describe))
    }

    /// Notification Windows « <nom> s'est connecté » (si le réglage est actif).
    pub fn notify_connected(&self, name: &str) {
        if !self.settings().notifications {
            return;
        }
        let result = self
            .app
            .notification()
            .builder()
            .title("axios")
            .body(format!("{name} s'est connecté"))
            .show();
        if let Err(e) = result {
            log::warn!("notification impossible : {e}");
        }
    }

    /// Sondage périodique du point d'accès (changements faits hors de l'application, perte et
    /// retour de la connexion, connexion partagée).
    pub fn spawn_poll(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let mut tick = interval(POLL_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                // Une opération en cours fait foi : on ne la perturbe pas.
                let Ok(_op) = this.op.try_lock() else {
                    continue;
                };
                match blocking_try(hotspot::info).await {
                    Ok(info) => {
                        this.sync_with(info, IFACE_ATTEMPTS_ADOPT).await;
                        this.auto_restart().await;
                    }
                    Err(AppError::Winsys(WinsysError::NoInternet)) => {
                        // Windows éteint le point d'accès quand la connexion disparaît.
                        this.update(|st| {
                            if st.snapshot.status == Status::On && !st.restart_pending {
                                log::info!("connexion internet perdue pendant le partage");
                                st.restart_pending = true;
                            }
                        });
                    }
                    Err(e) => log::debug!("sondage du point d'accès : {e}"),
                }
                this.refresh_source().await;
            }
        });
    }

    /// Arrêt de l'application : point d'accès, puis moteur. Chaque étape est bornée dans le temps.
    pub async fn shutdown(&self) {
        let _op = timeout(SHUTDOWN_STEP_TIMEOUT, self.op.lock()).await.ok();
        log::info!("arrêt de l'application");
        self.detach();
        match timeout(SHUTDOWN_STEP_TIMEOUT, blocking_try(hotspot::stop)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => log::warn!("arrêt du point d'accès : {e}"),
            Err(_) => log::warn!("arrêt du point d'accès : délai dépassé"),
        }
        let engine = lock(&self.engine).take();
        if let Some(engine) = engine {
            if timeout(SHUTDOWN_STEP_TIMEOUT, blocking(move || engine.shutdown()))
                .await
                .is_err()
            {
                log::warn!("arrêt du moteur : délai dépassé");
            }
        }
        lock(&self.engine_lock).take();
        // Dernière écriture synchrone : une sauvegarde en tâche de fond peut être interrompue
        // par la sortie du processus.
        self.devices.save_now();
        self.history.save_now();
    }
}
