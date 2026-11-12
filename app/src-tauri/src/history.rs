//! Historique de consommation (`history.json`) : heures sur 48 h, jours sur 60 jours,
//! totaux et par appareil. Alimenté chaque minute ; agrégé pour la vue « Activité ».

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{devices::DeviceKind, store::lenient};

pub const HOUR_MS: i64 = 3_600_000;
pub const DAY_MS: i64 = 24 * HOUR_MS;
/// Durée de conservation des heures.
const KEEP_HOURS: i64 = 48;
/// Durée de conservation des jours.
const KEEP_DAYS: i64 = 60;

/// Octets échangés pendant une période, au total et par appareil (`[descendant, montant]`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Slot {
    #[serde(deserialize_with = "lenient")]
    pub down: u64,
    #[serde(deserialize_with = "lenient")]
    pub up: u64,
    #[serde(deserialize_with = "lenient")]
    pub devices: BTreeMap<String, [u64; 2]>,
}

impl Slot {
    pub fn is_empty(&self) -> bool {
        self.down == 0 && self.up == 0 && self.devices.is_empty()
    }

    /// Ajoute du trafic à un appareil (et non au total, compté à part).
    pub fn add_device(&mut self, id: &str, down: u64, up: u64) {
        if down == 0 && up == 0 {
            return;
        }
        let entry = self.devices.entry(id.to_owned()).or_default();
        entry[0] = entry[0].saturating_add(down);
        entry[1] = entry[1].saturating_add(up);
    }

    fn merge(&mut self, other: &Slot) {
        self.down = self.down.saturating_add(other.down);
        self.up = self.up.saturating_add(other.up);
        for (id, [down, up]) in &other.devices {
            self.add_device(id, *down, *up);
        }
    }
}

/// Contenu de `history.json`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct History {
    /// Clé : début de l'heure (ms depuis l'époque Unix).
    #[serde(deserialize_with = "lenient")]
    pub hours: BTreeMap<i64, Slot>,
    /// Clé : numéro du jour local (jours depuis l'époque, décalage horaire appliqué).
    #[serde(deserialize_with = "lenient")]
    pub days: BTreeMap<i64, Slot>,
}

/// Période affichée par la vue « Activité ».
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Range {
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
    #[serde(rename = "30d")]
    Month,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Bucket {
    /// Début de la période (ms).
    pub t: i64,
    pub down: u64,
    pub up: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct UsageDevice {
    pub id: String,
    pub name: String,
    pub kind: DeviceKind,
    pub down: u64,
    pub up: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Usage {
    pub buckets: Vec<Bucket>,
    pub devices: Vec<UsageDevice>,
}

fn hour_start(now_ms: i64) -> i64 {
    now_ms.div_euclid(HOUR_MS) * HOUR_MS
}

/// Numéro du jour local ; `offset_ms` = heure locale − UTC.
fn local_day(now_ms: i64, offset_ms: i64) -> i64 {
    (now_ms + offset_ms).div_euclid(DAY_MS)
}

/// Début (ms UTC) du jour local numéro `day`.
fn day_start(day: i64, offset_ms: i64) -> i64 {
    day * DAY_MS - offset_ms
}

impl History {
    /// Ajoute le trafic d'une minute et purge ce qui dépasse la durée de conservation.
    pub fn record(&mut self, now_ms: i64, offset_ms: i64, slot: &Slot) {
        if !slot.is_empty() {
            self.hours
                .entry(hour_start(now_ms))
                .or_default()
                .merge(slot);
            self.days
                .entry(local_day(now_ms, offset_ms))
                .or_default()
                .merge(slot);
        }
        let oldest_hour = hour_start(now_ms) - (KEEP_HOURS - 1) * HOUR_MS;
        self.hours.retain(|&t, _| t >= oldest_hour);
        let oldest_day = local_day(now_ms, offset_ms) - (KEEP_DAYS - 1);
        self.days.retain(|&d, _| d >= oldest_day);
    }

    /// Agrège l'historique pour la période : 24 heures, ou 7 / 30 jours (le dernier est le
    /// jour ou l'heure en cours). `describe` donne le nom et le type actuels d'un appareil.
    pub fn usage(
        &self,
        range: Range,
        now_ms: i64,
        offset_ms: i64,
        describe: impl Fn(&str) -> (String, DeviceKind),
    ) -> Usage {
        // Périodes affichées, de la plus ancienne à la plus récente.
        let periods: Vec<(i64, Option<&Slot>)> = match range {
            Range::Day => {
                let last = hour_start(now_ms);
                (0..24)
                    .rev()
                    .map(|i| last - i * HOUR_MS)
                    .map(|t| (t, self.hours.get(&t)))
                    .collect()
            }
            Range::Week | Range::Month => {
                let n = if range == Range::Week { 7 } else { 30 };
                let today = local_day(now_ms, offset_ms);
                (0..n)
                    .rev()
                    .map(|i| today - i)
                    .map(|day| (day_start(day, offset_ms), self.days.get(&day)))
                    .collect()
            }
        };
        let mut buckets = Vec::with_capacity(periods.len());
        let mut per_device: HashMap<&str, [u64; 2]> = HashMap::new();
        for (t, slot) in periods {
            let (down, up) = slot.map_or((0, 0), |s| (s.down, s.up));
            buckets.push(Bucket { t, down, up });
            for (id, [d, u]) in slot.into_iter().flat_map(|s| &s.devices) {
                let e = per_device.entry(id.as_str()).or_default();
                e[0] = e[0].saturating_add(*d);
                e[1] = e[1].saturating_add(*u);
            }
        }
        let mut devices: Vec<UsageDevice> = per_device
            .into_iter()
            .filter(|(_, [d, u])| d.saturating_add(*u) > 0)
            .map(|(id, [down, up])| {
                let (name, kind) = describe(id);
                UsageDevice {
                    id: id.to_owned(),
                    name,
                    kind,
                    down,
                    up,
                }
            })
            .collect();
        devices.sort_by(|a, b| {
            (b.down.saturating_add(b.up))
                .cmp(&a.down.saturating_add(a.up))
                .then_with(|| a.id.cmp(&b.id))
        });
        Usage { buckets, devices }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-12 10:30 UTC.
    const NOW: i64 = 1_794_479_400_000;

    fn slot(down: u64, up: u64, devices: &[(&str, u64, u64)]) -> Slot {
        let mut s = Slot {
            down,
            up,
            ..Slot::default()
        };
        for (id, d, u) in devices {
            s.add_device(id, *d, *u);
        }
        s
    }

    fn describe(id: &str) -> (String, DeviceKind) {
        (format!("nom {id}"), DeviceKind::Phone)
    }

    #[test]
    fn vingt_quatre_heures() {
        let mut h = History::default();
        h.record(NOW, 0, &slot(100, 10, &[("A", 60, 6), ("B", 40, 4)]));
        h.record(NOW + 60_000, 0, &slot(50, 5, &[("A", 50, 5)]));
        h.record(NOW - 3 * HOUR_MS, 0, &slot(7, 1, &[("B", 7, 1)]));
        // Hors période (plus de 24 h) : compté dans les jours, pas dans les 24 h.
        h.record(NOW - 30 * HOUR_MS, 0, &slot(1000, 0, &[("C", 1000, 0)]));

        let u = h.usage(Range::Day, NOW + 120_000, 0, describe);
        assert_eq!(u.buckets.len(), 24);
        let last = u.buckets.last().unwrap();
        assert_eq!(last.t, hour_start(NOW));
        assert_eq!((last.down, last.up), (150, 15));
        assert_eq!(u.buckets[20].t, hour_start(NOW) - 3 * HOUR_MS);
        assert_eq!(u.buckets[20].down, 7);
        assert!(u.buckets.windows(2).all(|w| w[1].t - w[0].t == HOUR_MS));

        let ids: Vec<_> = u.devices.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, ["A", "B"], "triés par volume, C hors période");
        assert_eq!((u.devices[0].down, u.devices[0].up), (110, 11));
        assert_eq!(u.devices[0].name, "nom A");
        assert_eq!(u.devices[0].kind, DeviceKind::Phone);
    }

    #[test]
    fn jours_avec_decalage_horaire() {
        let offset = 2 * HOUR_MS; // UTC+2
        let mut h = History::default();
        h.record(NOW, offset, &slot(10, 1, &[]));
        h.record(NOW - DAY_MS, offset, &slot(20, 2, &[]));
        h.record(NOW - 10 * DAY_MS, offset, &slot(30, 3, &[("X", 30, 3)]));

        let week = h.usage(Range::Week, NOW, offset, describe);
        assert_eq!(week.buckets.len(), 7);
        let today = week.buckets.last().unwrap();
        // Minuit local = 22:00 UTC la veille.
        assert_eq!((today.t + offset).rem_euclid(DAY_MS), 0);
        assert!(today.t <= NOW && NOW < today.t + DAY_MS);
        assert_eq!(today.down, 10);
        assert_eq!(week.buckets[5].down, 20);
        assert!(week.devices.is_empty());

        let month = h.usage(Range::Month, NOW, offset, describe);
        assert_eq!(month.buckets.len(), 30);
        assert_eq!(month.buckets[19].down, 30);
        assert_eq!(month.devices.len(), 1);
    }

    #[test]
    fn purge_des_anciennes_periodes() {
        let mut h = History::default();
        h.record(NOW - 100 * DAY_MS, 0, &slot(1, 1, &[]));
        h.record(NOW - 49 * HOUR_MS, 0, &slot(1, 1, &[]));
        h.record(NOW, 0, &slot(1, 1, &[]));
        assert_eq!(h.hours.len(), 1);
        assert_eq!(h.days.len(), 2);
        // Une minute vide purge aussi, sans créer de période.
        h.record(NOW + 61 * DAY_MS, 0, &Slot::default());
        assert!(h.hours.is_empty() && h.days.is_empty());
    }

    #[test]
    fn json_tolerant_et_aller_retour() {
        let mut h = History::default();
        h.record(NOW, 0, &slot(5, 6, &[("AA:BB", 5, 6)]));
        let text = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<History>(&text).unwrap(), h);

        let h: History = serde_json::from_str(r#"{"hours":"x","days":{}}"#).unwrap();
        assert!(h.hours.is_empty());
    }

    #[test]
    fn json_de_l_usage() {
        let h = History::default();
        let u = h.usage(Range::Day, NOW, 0, describe);
        let v = serde_json::to_value(&u).unwrap();
        assert_eq!(v["buckets"].as_array().unwrap().len(), 24);
        assert!(v["buckets"][0].get("t").is_some());
        let r: Range = serde_json::from_str(r#""30d""#).unwrap();
        assert_eq!(r, Range::Month);
    }
}
