//! Relevé périodique, dans le journal, du trafic relayé par le moteur (diagnostic).

use pw_engine::EngineStats;

/// Période conseillée entre deux relevés, en secondes.
pub const PERIOD_SECS: u64 = 30;

/// Nombre total de paquets relayés (dans les deux sens).
pub fn relayed_packets(engine: &EngineStats) -> u64 {
    let p = &engine.packets;
    p.fwd_tcp + p.fwd_udp + p.reflected_out + p.udp_back
}

/// Consigne les compteurs s'il y a eu du trafic depuis le relevé précédent ;
/// renvoie le total de paquets à passer au prochain appel.
pub fn log_if_changed(engine: &EngineStats, last_total: u64) -> u64 {
    let total = relayed_packets(engine);
    if total != last_total {
        log::info!(
            "moteur : ↓ {} o ↑ {} o | tcp {} actives, udp {} sessions | paquets {:?}",
            engine.total.down_bytes,
            engine.total.up_bytes,
            engine.active_tcp,
            engine.active_udp,
            engine.packets
        );
    }
    total
}
