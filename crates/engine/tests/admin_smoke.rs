//! Tests d'intégration nécessitant les droits administrateur (pilote WinDivert).
//! Lancer avec : `cargo test -p pw-engine -- --ignored` depuis une console élevée.
//! Le test de bout en bout avec un téléphone réel reste manuel.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use pw_engine::{Blocklist, Engine, EngineConfig, Policy};

fn config() -> EngineConfig {
    EngineConfig {
        gateway: Ipv4Addr::new(192, 168, 137, 1),
        prefix_len: 24,
        tcp_port: 38229,
        windivert_dll: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/windivert/WinDivert.dll"),
    }
}

#[test]
#[ignore = "nécessite les droits administrateur et le pilote WinDivert"]
fn engine_starts_idles_and_shuts_down() {
    let engine = Engine::start(config()).expect("démarrage du moteur");
    engine.set_hotspot_interface(None);
    std::thread::sleep(Duration::from_millis(300));
    let stats = engine.stats();
    assert_eq!(stats.active_tcp, 0);
    assert_eq!(stats.active_udp, 0);
    assert_eq!(stats.ads_blocked, 0);

    // Changer la politique est immédiat et sans effet de bord au repos.
    let mut policy = Policy {
        isolate: true,
        ..Policy::default()
    };
    policy.dns.blocklist = Some(Blocklist::parse("0.0.0.0 ads.example.com").into());
    engine.set_policy(policy);
    engine.set_policy(Policy::default());
    engine.shutdown();

    // Le port doit être libéré : un second démarrage réussit.
    let again = Engine::start(config()).expect("redémarrage");
    drop(again);
}
