//! Partage automatique : version sans interface de Partage Wi-Fi.
//!
//! L'utilisateur allume le point d'accès mobile depuis Windows ; cet exécutable, lancé à
//! l'ouverture de session, fait tourner le moteur tant que le point d'accès est allumé.
//!
//! - Double-clic : active le partage automatique, ou propose de le désactiver s'il tourne.
//! - [`BACKGROUND_ARG`] : instance d'arrière-plan (lancée par la tâche planifiée).

pub mod dialog;
pub mod install;
pub mod monitor;

use std::process::ExitCode;

use pw_support::{logging, subnet_cidr, PREFIX_LEN, TCP_PORT};
use pw_winsys::{
    firewall, net,
    sync::{NamedEvent, NamedLock},
};

/// Argument de l'instance d'arrière-plan.
pub const BACKGROUND_ARG: &str = "--arriere-plan";
pub const TASK_NAME: &str = "PartageWiFi-Auto";
pub const FIREWALL_RULE: &str = "PartageWiFi Auto";
/// Tenu par l'instance d'arrière-plan pendant toute sa vie.
pub const INSTANCE_LOCK: &str = r"Global\PartageWiFi.Auto";
/// Demande d'arrêt adressée à l'instance d'arrière-plan.
pub const STOP_SIGNAL: &str = r"Global\PartageWiFi.Auto.Arret";

const LOG_FILE: &str = "partage-wifi-auto.log";

pub fn main() -> ExitCode {
    logging::init(LOG_FILE, "Partage Wi-Fi Auto");
    if std::env::args().skip(1).any(|a| a == BACKGROUND_ARG) {
        run_background()
    } else {
        toggle()
    }
}

/// Double-clic : active, ou propose de désactiver.
fn toggle() -> ExitCode {
    let running = match install::is_running() {
        Ok(running) => running,
        Err(e) => {
            dialog::error(&e.to_string());
            return ExitCode::FAILURE;
        }
    };
    let result = if running {
        if !dialog::confirm("Le partage automatique est actif.\n\nLe désactiver ?") {
            return ExitCode::SUCCESS;
        }
        install::disable().map(|()| "Partage automatique désactivé.")
    } else {
        install::enable().map(|()| {
            "Partage automatique activé.\n\n\
             Allumez le point d'accès mobile de Windows : vos appareils auront internet."
        })
    };
    match result {
        Ok(message) => {
            dialog::info(message);
            ExitCode::SUCCESS
        }
        Err(e) => {
            log::error!("{e}");
            dialog::error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

/// Instance d'arrière-plan : surveille le point d'accès jusqu'au signal d'arrêt.
fn run_background() -> ExitCode {
    let _instance = match NamedLock::try_acquire(INSTANCE_LOCK) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            log::info!("instance déjà active");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            log::error!("verrou d'instance : {e}");
            return ExitCode::FAILURE;
        }
    };
    let stop = match NamedEvent::create(STOP_SIGNAL) {
        Ok(event) => event,
        Err(e) => {
            log::error!("signal d'arrêt : {e}");
            return ExitCode::FAILURE;
        }
    };

    let gateway = net::ics_gateway();
    log::info!("passerelle ICS : {gateway}");
    allow_proxy_in_firewall(gateway);

    monitor::Monitor::new(monitor::System::new(gateway)).run(&stop);
    log::info!("fin du partage automatique");
    ExitCode::SUCCESS
}

/// Autorise le proxy TCP local depuis le réseau du point d'accès. Non fatal.
fn allow_proxy_in_firewall(gateway: std::net::Ipv4Addr) {
    let result = std::env::current_exe()
        .map_err(|e| e.to_string())
        .and_then(|exe| {
            firewall::ensure_rule(
                FIREWALL_RULE,
                &exe,
                TCP_PORT,
                &subnet_cidr(gateway, PREFIX_LEN),
            )
            .map_err(|e| e.to_string())
        });
    if let Err(e) = result {
        log::error!("règle de pare-feu : {e}");
    }
}
