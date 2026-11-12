//! Heure courante (ms depuis l'époque Unix) et décalage du fuseau local.

use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};

/// `TIME_ZONE_ID_STANDARD` / `TIME_ZONE_ID_DAYLIGHT` / `TIME_ZONE_ID_INVALID`.
const TZ_STANDARD: u32 = 1;
const TZ_DAYLIGHT: u32 = 2;
const TZ_INVALID: u32 = u32::MAX;

/// Millisecondes depuis l'époque Unix.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Décalage heure locale − UTC, en millisecondes (0 si inconnu).
pub fn local_offset_ms() -> i64 {
    let mut tzi = TIME_ZONE_INFORMATION::default();
    // SAFETY: `tzi` est une structure valide, remplie par Windows.
    let id = unsafe { GetTimeZoneInformation(&mut tzi) };
    let extra = match id {
        TZ_INVALID => return 0,
        TZ_DAYLIGHT => tzi.DaylightBias,
        TZ_STANDARD => tzi.StandardBias,
        _ => 0,
    };
    // UTC = heure locale + biais (minutes).
    -i64::from(tzi.Bias + extra) * 60_000
}
