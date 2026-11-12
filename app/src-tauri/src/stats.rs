//! Statistiques : tâche de 1 s qui fusionne compteurs du moteur et appareils connectés,
//! publie l'événement `stats`, tient la correspondance IP ↔ MAC de la politique à jour,
//! notifie les nouveaux appareils et alimente l'historique chaque minute.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};

use pw_engine::{Counters, EngineStats};
use pw_support::activity;
use pw_winsys::{
    hotspot::{self, HotspotClient},
    net,
};
use serde::Serialize;
use tauri::Emitter;
use tokio::time::{interval, MissedTickBehavior};

use crate::{
    clock,
    controller::{Controller, Status},
    devices::{display_name, guess_kind, normalize_id, vendor_label, DeviceKind, DeviceStore},
    error::blocking,
    history::Slot,
    policy::Peer,
};

/// Fenêtre de lissage des débits.
const RATE_WINDOW: Duration = Duration::from_secs(2);
/// Une IP vue par le moteur sans être cliente du point d'accès n'est listée que si elle a
/// échangé du trafic dans cet intervalle.
const ACTIVE_WINDOW: Duration = Duration::from_secs(60);
/// Délai d'attente du nom d'hôte avant la notification d'un nouvel appareil.
const NOTIFY_DELAY: Duration = Duration::from_secs(5);
/// Période d'enregistrement de l'historique, en secondes.
const HISTORY_PERIOD_SECS: u64 = 60;
/// Période de vérification de l'âge de la liste de blocage, en secondes.
const BLOCKLIST_CHECK_SECS: u64 = 12 * 3600;

/// Appareil publié à l'interface (forme `Device` de `types.ts`).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub alias: String,
    pub hostname: String,
    pub vendor: String,
    pub kind: DeviceKind,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub connected_at: Option<i64>,
    pub rate_down: u64,
    pub rate_up: u64,
    pub total_down: u64,
    pub total_up: u64,
    pub blocked: bool,
    /// Débit maximal propre (Mb/s), `None` = réglage par défaut.
    pub limit: Option<f64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub rate_down: u64,
    pub rate_up: u64,
    pub total_down: u64,
    pub total_up: u64,
    pub ads_blocked: u64,
    pub devices: Vec<Device>,
}

/// Débit lissé à partir de compteurs cumulatifs.
#[derive(Default)]
struct RateWindow {
    samples: VecDeque<(Instant, Counters)>,
}

impl RateWindow {
    /// Ajoute un échantillon et renvoie `(descendant, montant)` en octets/s.
    fn push(&mut self, now: Instant, counters: Counters) -> (u64, u64) {
        self.samples.push_back((now, counters));
        // Garde l'échantillon le plus récent à l'instant `now - RATE_WINDOW` ou avant.
        while self.samples.len() > 2 && now.duration_since(self.samples[1].0) >= RATE_WINDOW {
            self.samples.pop_front();
        }
        let Some(&(t0, c0)) = self.samples.front() else {
            return (0, 0);
        };
        let dt = now.duration_since(t0).as_secs_f64();
        if dt <= 0.0 {
            return (0, 0);
        }
        let rate = |new: u64, old: u64| (new.saturating_sub(old) as f64 / dt).round() as u64;
        (
            rate(counters.down_bytes, c0.down_bytes),
            rate(counters.up_bytes, c0.up_bytes),
        )
    }
}

/// Appareils connus côté système (clients WinRT, table de voisinage).
#[derive(Default)]
struct Topology {
    clients: Vec<HotspotClient>,
    neighbors: Vec<(Ipv4Addr, String)>,
}

fn fetch_topology(if_index: Option<u32>) -> Topology {
    let clients = hotspot::clients().unwrap_or_else(|e| {
        log::debug!("clients du point d'accès : {e}");
        Vec::new()
    });
    let neighbors = if_index.map(net::neighbors).unwrap_or_default();
    Topology { clients, neighbors }
}

/// Identité d'un appareil, avant ajout des compteurs.
#[derive(Debug, PartialEq, Eq)]
struct DeviceInfo {
    id: String,
    name: String,
    ip: Option<Ipv4Addr>,
    mac: Option<String>,
}

/// Union des clients du point d'accès et des IP vues par le moteur, rapprochées par la table de voisinage.
fn merge_devices(topology: &Topology, seen_ips: &HashSet<Ipv4Addr>) -> Vec<DeviceInfo> {
    let ip_by_mac: HashMap<String, Ipv4Addr> = topology
        .neighbors
        .iter()
        .map(|(ip, mac)| (normalize_id(mac), *ip))
        .collect();
    let mac_by_ip: HashMap<Ipv4Addr, String> = ip_by_mac
        .iter()
        .map(|(mac, ip)| (*ip, mac.clone()))
        .collect();

    let mut devices = Vec::new();
    let mut used_ips = HashSet::new();
    let mut used_macs = HashSet::new();

    for client in &topology.clients {
        let mac = normalize_id(&client.mac);
        if !used_macs.insert(mac.clone()) {
            continue;
        }
        let ip = ip_by_mac.get(&mac).copied();
        used_ips.extend(ip);
        let name = client
            .host_names
            .iter()
            .map(|n| n.trim())
            .find(|n| !n.is_empty())
            .unwrap_or_default()
            .to_owned();
        devices.push(DeviceInfo {
            id: mac.clone(),
            name,
            ip,
            mac: Some(mac),
        });
    }

    for &ip in seen_ips {
        if used_ips.contains(&ip) {
            continue;
        }
        let mac = mac_by_ip.get(&ip).cloned();
        if mac.as_ref().is_some_and(|m| used_macs.contains(m)) {
            continue;
        }
        devices.push(DeviceInfo {
            id: mac.clone().unwrap_or_else(|| ip.to_string()),
            name: String::new(),
            ip: Some(ip),
            mac,
        });
    }

    // Ordre stable : par IP (inconnues à la fin), puis par identifiant.
    devices.sort_by(|a, b| (a.ip.is_none(), a.ip, &a.id).cmp(&(b.ip.is_none(), b.ip, &b.id)));
    devices
}

/// Appareils présents pour la politique : table de voisinage et appareils listés.
fn peers_of(topology: &Topology, infos: &[DeviceInfo]) -> Vec<Peer> {
    let neighbors = topology.neighbors.iter().map(|(ip, mac)| Peer {
        ip: *ip,
        mac: Some(normalize_id(mac)),
    });
    let listed = infos.iter().filter_map(|d| {
        d.ip.map(|ip| Peer {
            ip,
            mac: d.mac.clone(),
        })
    });
    let mut peers: Vec<Peer> = neighbors.chain(listed).collect();
    peers.sort();
    peers.dedup_by_key(|p| p.ip);
    peers
}

/// Résultat d'une seconde de calcul.
#[derive(Default)]
struct Tick {
    stats: Stats,
    peers: Vec<Peer>,
    /// Noms des appareils à annoncer (première apparition dans la session).
    arrivals: Vec<String>,
    /// `(id, nom d'hôte)` des appareils identifiés par leur MAC.
    hostnames: Vec<(String, String)>,
    /// IP → identifiant de l'appareil, pour l'historique.
    ids: HashMap<Ipv4Addr, String>,
}

#[derive(Default)]
struct Tracker {
    total: RateWindow,
    devices: HashMap<Ipv4Addr, RateWindow>,
    /// Dernière évolution des compteurs de chaque IP vue par le moteur.
    activity: HashMap<Ipv4Addr, (Counters, Instant)>,
    /// Première apparition de chaque appareil dans la session de partage (ms).
    connected_at: HashMap<String, i64>,
    /// Appareils apparus dont la notification attend le nom d'hôte.
    pending: HashMap<String, Instant>,
}

impl Tracker {
    /// IP vues par le moteur ayant échangé du trafic récemment.
    fn recent_ips(&mut self, now: Instant, engine: &EngineStats) -> HashSet<Ipv4Addr> {
        for (ip, counters) in &engine.per_device {
            match self.activity.get_mut(ip) {
                Some(entry) if entry.0 == *counters => {}
                Some(entry) => *entry = (*counters, now),
                None => {
                    self.activity.insert(*ip, (*counters, now));
                }
            }
        }
        self.activity
            .iter()
            .filter(|(_, (_, at))| now.duration_since(*at) < ACTIVE_WINDOW)
            .map(|(ip, _)| *ip)
            .collect()
    }

    fn compute(
        &mut self,
        now: Instant,
        now_ms: i64,
        engine: &EngineStats,
        topology: &Topology,
        active: bool,
        prefs: &DeviceStore,
    ) -> Tick {
        let (rate_down, rate_up) = self.total.push(now, engine.total);
        let mut tick = Tick {
            stats: Stats {
                rate_down,
                rate_up,
                total_down: engine.total.down_bytes,
                total_up: engine.total.up_bytes,
                ads_blocked: engine.ads_blocked,
                devices: Vec::new(),
            },
            ..Tick::default()
        };
        let seen = self.recent_ips(now, engine);
        if !active {
            self.devices.clear();
            self.connected_at.clear();
            self.pending.clear();
            return tick;
        }

        let infos = merge_devices(topology, &seen);
        tick.peers = peers_of(topology, &infos);
        let live: HashSet<Ipv4Addr> = infos.iter().filter_map(|d| d.ip).collect();
        self.devices.retain(|ip, _| live.contains(ip));
        let present: HashSet<&str> = infos.iter().map(|d| d.id.as_str()).collect();
        self.pending.retain(|id, _| present.contains(id.as_str()));

        for info in infos {
            let counters = info
                .ip
                .and_then(|ip| engine.per_device.get(&ip).copied())
                .unwrap_or_default();
            let (rate_down, rate_up) = info.ip.map_or((0, 0), |ip| {
                self.devices.entry(ip).or_default().push(now, counters)
            });
            let entry = prefs.get(&info.id);
            let alias = entry.map(|e| e.alias.clone()).unwrap_or_default();
            let vendor = vendor_label(info.mac.as_deref());
            let kind = match guess_kind(&info.name) {
                DeviceKind::Other => guess_kind(&alias),
                kind => kind,
            };
            if !self.connected_at.contains_key(&info.id) {
                self.connected_at.insert(info.id.clone(), now_ms);
                self.pending.insert(info.id.clone(), now);
            }
            if let Some(&since) = self.pending.get(&info.id) {
                let named = !alias.is_empty() || !info.name.is_empty();
                if named || now.duration_since(since) >= NOTIFY_DELAY {
                    self.pending.remove(&info.id);
                    tick.arrivals
                        .push(display_name(&info.id, &alias, &info.name, &vendor));
                }
            }
            if let Some(ip) = info.ip {
                tick.ids.insert(ip, info.id.clone());
            }
            if info.mac.is_some() && !info.name.is_empty() {
                tick.hostnames.push((info.id.clone(), info.name.clone()));
            }
            tick.stats.devices.push(Device {
                connected_at: self.connected_at.get(&info.id).copied(),
                id: info.id,
                alias,
                hostname: info.name,
                vendor,
                kind,
                ip: info.ip.map(|ip| ip.to_string()),
                mac: info.mac,
                rate_down,
                rate_up,
                total_down: counters.down_bytes,
                total_up: counters.up_bytes,
                blocked: entry.is_some_and(|e| e.blocked),
                limit: entry.and_then(|e| e.limit),
            });
        }
        tick
    }
}

/// Octets écoulés entre deux relevés d'un compteur cumulatif (remise à zéro comprise).
fn delta(new: u64, old: u64) -> u64 {
    if new >= old {
        new - old
    } else {
        new
    }
}

/// Accumule le trafic entre deux enregistrements de l'historique.
#[derive(Default)]
struct UsageRecorder {
    last_total: Counters,
    last: HashMap<Ipv4Addr, Counters>,
    pending: Slot,
}

impl UsageRecorder {
    /// Ajoute le trafic depuis le relevé précédent ; `ids` nomme les IP (sinon l'IP sert
    /// d'identifiant).
    fn observe(&mut self, engine: &EngineStats, ids: &HashMap<Ipv4Addr, String>) {
        let total = engine.total;
        self.pending.down = self
            .pending
            .down
            .saturating_add(delta(total.down_bytes, self.last_total.down_bytes));
        self.pending.up = self
            .pending
            .up
            .saturating_add(delta(total.up_bytes, self.last_total.up_bytes));
        self.last_total = total;
        for (ip, counters) in &engine.per_device {
            let old = self.last.insert(*ip, *counters).unwrap_or_default();
            let down = delta(counters.down_bytes, old.down_bytes);
            let up = delta(counters.up_bytes, old.up_bytes);
            match ids.get(ip) {
                Some(id) => self.pending.add_device(id, down, up),
                None => self.pending.add_device(&ip.to_string(), down, up),
            }
        }
    }

    fn take(&mut self) -> Slot {
        std::mem::take(&mut self.pending)
    }
}

/// Lance la tâche d'émission de l'événement `stats` (chaque seconde).
pub fn spawn(controller: Arc<Controller>) {
    tauri::async_runtime::spawn(async move {
        let mut tick = interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut tracker = Tracker::default();
        let mut recorder = UsageRecorder::default();
        let mut topology = Topology::default();
        let mut seconds: u64 = 0;
        let mut last_logged_packets = 0;
        loop {
            tick.tick().await;
            seconds += 1;
            let active = controller.snapshot().status == Status::On;
            if active {
                let if_index = controller.if_index();
                match blocking(move || fetch_topology(if_index)).await {
                    Ok(t) => topology = t,
                    Err(e) => log::debug!("topologie : {e}"),
                }
            } else {
                topology = Topology::default();
            }
            let engine = controller.engine_stats();
            if seconds.is_multiple_of(activity::PERIOD_SECS) {
                last_logged_packets = activity::log_if_changed(&engine, last_logged_packets);
            }
            let prefs = controller.device_prefs();
            let result = tracker.compute(
                Instant::now(),
                clock::now_ms(),
                &engine,
                &topology,
                active,
                &prefs,
            );

            controller.set_peers(result.peers);
            for name in &result.arrivals {
                log::info!("nouvel appareil : {name}");
                controller.notify_connected(name);
            }
            controller.remember_hostnames(&result.hostnames).await;
            recorder.observe(&engine, &result.ids);
            if seconds.is_multiple_of(HISTORY_PERIOD_SECS) {
                controller.record_usage(recorder.take()).await;
            }
            if seconds.is_multiple_of(BLOCKLIST_CHECK_SECS) && controller.settings().ad_block {
                controller.refresh_blocklist();
            }

            if let Err(e) = controller.app().emit("stats", &result.stats) {
                log::debug!("émission de « stats » impossible : {e}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(down: u64, up: u64) -> Counters {
        Counters {
            up_bytes: up,
            down_bytes: down,
        }
    }

    #[test]
    fn debit_lisse_sur_deux_secondes() {
        let t0 = Instant::now();
        let mut w = RateWindow::default();
        assert_eq!(w.push(t0, counters(0, 0)), (0, 0));
        assert_eq!(
            w.push(t0 + Duration::from_secs(1), counters(1000, 100)),
            (1000, 100)
        );
        // Rafale puis silence : le lissage étale sur la fenêtre.
        assert_eq!(
            w.push(t0 + Duration::from_secs(2), counters(1000, 100)),
            (500, 50)
        );
        assert_eq!(
            w.push(t0 + Duration::from_secs(3), counters(1000, 100)),
            (0, 0)
        );
    }

    #[test]
    fn compteur_remis_a_zero_ne_deborde_pas() {
        let t0 = Instant::now();
        let mut w = RateWindow::default();
        w.push(t0, counters(500, 500));
        assert_eq!(w.push(t0 + Duration::from_secs(1), counters(0, 0)), (0, 0));
    }

    fn client(mac: &str, names: &[&str]) -> HotspotClient {
        HotspotClient {
            mac: mac.to_owned(),
            host_names: names.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn fusion_clients_et_ip_vues() {
        let ip1 = Ipv4Addr::new(192, 168, 137, 10);
        let ip2 = Ipv4Addr::new(192, 168, 137, 11);
        let topology = Topology {
            clients: vec![client("aa:bb:cc:dd:ee:01", &["", "tel"])],
            neighbors: vec![
                (ip1, "AA-BB-CC-DD-EE-01".into()),
                (ip2, "AA:BB:CC:DD:EE:02".into()),
            ],
        };
        let seen: HashSet<_> = [ip1, ip2].into();
        let devices = merge_devices(&topology, &seen);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].id, "AA:BB:CC:DD:EE:01");
        assert_eq!(devices[0].name, "tel");
        assert_eq!(devices[0].ip, Some(ip1));
        assert_eq!(devices[1].id, "AA:BB:CC:DD:EE:02");
        assert_eq!(devices[1].name, "");
    }

    #[test]
    fn ip_sans_voisin_utilise_l_ip_comme_id() {
        let ip = Ipv4Addr::new(192, 168, 137, 20);
        let devices = merge_devices(&Topology::default(), &[ip].into());
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, "192.168.137.20");
        assert_eq!(devices[0].mac, None);
    }

    fn engine(devices: &[(Ipv4Addr, u64, u64)]) -> EngineStats {
        let mut stats = EngineStats::default();
        for &(ip, down, up) in devices {
            stats.per_device.insert(ip, counters(down, up));
            stats.total.down_bytes += down;
            stats.total.up_bytes += up;
        }
        stats
    }

    #[test]
    fn appareil_publie_avec_ses_preferences() {
        let ip = Ipv4Addr::new(192, 168, 137, 10);
        let mac = "AA:BB:CC:DD:EE:01";
        let topology = Topology {
            clients: vec![client(mac, &["Galaxy-S23"])],
            neighbors: vec![(ip, mac.into())],
        };
        let mut prefs = DeviceStore::default();
        prefs.set_alias(mac, "Tel de Léa");
        prefs.set_blocked(mac, true);
        prefs.set_limit(mac, Some(5.0));
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let tick = tracker.compute(t0, 1000, &engine(&[(ip, 10, 2)]), &topology, true, &prefs);
        let d = &tick.stats.devices[0];
        assert_eq!(d.alias, "Tel de Léa");
        assert_eq!(d.hostname, "Galaxy-S23");
        assert_eq!(d.kind, DeviceKind::Phone);
        assert_eq!(d.connected_at, Some(1000));
        assert!(d.blocked);
        assert_eq!(d.limit, Some(5.0));
        assert_eq!((d.total_down, d.total_up), (10, 2));
        assert_eq!(tick.arrivals, ["Tel de Léa"]);
        assert_eq!(
            tick.peers,
            [Peer {
                ip,
                mac: Some(mac.into())
            }]
        );
        assert_eq!(tick.ids.get(&ip).map(String::as_str), Some(mac));

        // Seconde suivante : même heure de connexion, pas de nouvelle annonce.
        let tick = tracker.compute(
            t0 + Duration::from_secs(1),
            2000,
            &engine(&[(ip, 10, 2)]),
            &topology,
            true,
            &prefs,
        );
        assert_eq!(tick.stats.devices[0].connected_at, Some(1000));
        assert!(tick.arrivals.is_empty());

        let json = serde_json::to_value(&tick.stats).unwrap();
        assert_eq!(json["devices"][0]["connectedAt"], 1000);
        assert_eq!(json["devices"][0]["kind"], "phone");
        assert!(json.get("adsBlocked").is_some());
    }

    #[test]
    fn annonce_differee_sans_nom() {
        let mac = "AA:BB:CC:DD:EE:09";
        let topology = Topology {
            clients: vec![client(mac, &[])],
            neighbors: vec![],
        };
        let prefs = DeviceStore::default();
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let stats = EngineStats::default();
        let tick = tracker.compute(t0, 0, &stats, &topology, true, &prefs);
        assert!(tick.arrivals.is_empty(), "attente du nom d'hôte");
        let tick = tracker.compute(t0 + NOTIFY_DELAY, 0, &stats, &topology, true, &prefs);
        assert_eq!(tick.arrivals, [mac]);
    }

    #[test]
    fn ip_inactive_retiree_de_la_liste() {
        let ip = Ipv4Addr::new(192, 168, 137, 30);
        let mut tracker = Tracker::default();
        let prefs = DeviceStore::default();
        let topo = Topology::default();
        let t0 = Instant::now();
        let stats = engine(&[(ip, 5, 5)]);
        let tick = tracker.compute(t0, 0, &stats, &topo, true, &prefs);
        assert_eq!(tick.stats.devices.len(), 1);
        let later = t0 + ACTIVE_WINDOW;
        let tick = tracker.compute(later, 0, &stats, &topo, true, &prefs);
        assert!(
            tick.stats.devices.is_empty(),
            "plus de trafic depuis une minute"
        );
    }

    #[test]
    fn partage_arrete_remet_la_session_a_zero() {
        let mac = "AA:BB:CC:DD:EE:01";
        let topology = Topology {
            clients: vec![client(mac, &["pc"])],
            neighbors: vec![],
        };
        let prefs = DeviceStore::default();
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let stats = EngineStats::default();
        tracker.compute(t0, 1, &stats, &topology, true, &prefs);
        let off = tracker.compute(t0, 2, &stats, &topology, false, &prefs);
        assert!(off.stats.devices.is_empty());
        let tick = tracker.compute(t0, 3, &stats, &topology, true, &prefs);
        assert_eq!(tick.stats.devices[0].connected_at, Some(3));
        assert_eq!(tick.arrivals, ["pc"]);
    }

    #[test]
    fn historique_par_appareil() {
        let ip1 = Ipv4Addr::new(192, 168, 137, 10);
        let ip2 = Ipv4Addr::new(192, 168, 137, 11);
        let ids: HashMap<_, _> = [(ip1, "MAC1".to_owned())].into();
        let mut r = UsageRecorder::default();
        r.observe(&engine(&[(ip1, 100, 10), (ip2, 50, 5)]), &ids);
        r.observe(&engine(&[(ip1, 150, 20), (ip2, 50, 5)]), &ids);
        let slot = r.take();
        assert_eq!((slot.down, slot.up), (200, 25));
        assert_eq!(slot.devices.get("MAC1"), Some(&[150, 20]));
        assert_eq!(slot.devices.get("192.168.137.11"), Some(&[50, 5]));

        // Rien de neuf : minute vide.
        r.observe(&engine(&[(ip1, 150, 20), (ip2, 50, 5)]), &ids);
        assert!(r.take().is_empty());
        // Compteurs remis à zéro (moteur redémarré) : la nouvelle valeur compte entièrement.
        r.observe(&engine(&[(ip1, 30, 3)]), &ids);
        let slot = r.take();
        assert_eq!(slot.devices.get("MAC1"), Some(&[30, 3]));
        assert_eq!(delta(5, 10), 5);
    }
}
