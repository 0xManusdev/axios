//! Règles du pare-feu Windows via COM (`INetFwPolicy2`), sans `netsh`.

use std::path::Path;

use windows::core::BSTR;
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW,
    NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_PROFILE2_ALL,
    NET_FW_RULE_DIR_IN,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

use crate::error::{Context, Result, WinsysError};

/// Garde-fou contre une boucle infinie si Windows renvoie toujours la règle.
const MAX_DUPLICATES: usize = 32;

fn rules() -> Result<INetFwRules> {
    crate::com::ensure();
    // SAFETY: création COM standard d'un objet in-process.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .ctx("Ouverture du pare-feu Windows")?;
    // SAFETY: appel COM sur une interface valide.
    unsafe { policy.Rules() }.ctx("Lecture des règles du pare-feu")
}

fn delete_all(rules: &INetFwRules, name: &BSTR) -> Result<()> {
    for _ in 0..MAX_DUPLICATES {
        // SAFETY: appels COM sur une interface valide ; `Item` échoue si la règle n'existe pas.
        if unsafe { rules.Item(name) }.is_err() {
            return Ok(());
        }
        // SAFETY: idem.
        unsafe { rules.Remove(name) }.ctx("Suppression de la règle de pare-feu")?;
    }
    Ok(())
}

/// Crée ou remplace une règle entrante autorisant TCP `port` depuis `remote` pour `program`, tous profils.
pub fn ensure_rule(name: &str, program: &Path, port: u16, remote: &str) -> Result<()> {
    let program = program
        .to_str()
        .ok_or_else(|| WinsysError::InvalidPath(program.display().to_string()))?;
    let rules = rules()?;
    let bname = BSTR::from(name);
    delete_all(&rules, &bname)?;

    // SAFETY: création COM standard d'un objet in-process.
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .ctx("Création de la règle de pare-feu")?;
    // SAFETY: appels COM sur une interface valide ; les BSTR vivent pendant chaque appel.
    (|| unsafe {
        rule.SetName(&bname)?;
        rule.SetDescription(&BSTR::from("Partage Wi-Fi : proxy TCP local"))?;
        rule.SetApplicationName(&BSTR::from(program))?;
        rule.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)?;
        rule.SetLocalPorts(&BSTR::from(port.to_string()))?;
        rule.SetRemoteAddresses(&BSTR::from(remote))?;
        rule.SetDirection(NET_FW_RULE_DIR_IN)?;
        rule.SetAction(NET_FW_ACTION_ALLOW)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
        rule.SetEnabled(VARIANT_TRUE)
    })()
    .ctx("Configuration de la règle de pare-feu")?;
    // SAFETY: appel COM sur une interface valide.
    unsafe { rules.Add(&rule) }.ctx("Ajout de la règle de pare-feu")?;
    log::info!("règle de pare-feu « {name} » créée (TCP {port} depuis {remote})");
    Ok(())
}

/// Supprime la règle `name` (sans erreur si elle n'existe pas).
pub fn remove_rule(name: &str) -> Result<()> {
    let rules = rules()?;
    delete_all(&rules, &BSTR::from(name))?;
    log::info!("règle de pare-feu « {name} » supprimée");
    Ok(())
}

/// Numéro de protocole IP d'ICMPv4 (absent de `NET_FW_IP_PROTOCOL`).
const IP_PROTOCOL_ICMPV4: i32 = 1;

/// Noms des règles d'isolation.
const ISOLATION_TCP: &str = "axios-isolation-tcp";
const ISOLATION_UDP: &str = "axios-isolation-udp";
const ISOLATION_ICMP: &str = "axios-isolation-icmp";
/// Ports UDP laissés ouverts : DNS et DHCP.
const ISOLATION_UDP_KEEP: [u16; 2] = [53, 67];

/// Plages de ports 1–65535 sauf `excluded`, au format du pare-feu : `"1-8228,8230-65535"`.
/// Le port 0 est ignoré ; vide si tous les ports sont exclus.
fn ports_except(excluded: &[u16]) -> String {
    let mut excluded: Vec<u16> = excluded.iter().copied().filter(|&p| p != 0).collect();
    excluded.sort_unstable();
    excluded.dedup();
    let mut ranges = Vec::new();
    let mut start: u32 = 1;
    for port in excluded.into_iter().map(u32::from).chain([65_536]) {
        if port > start {
            let end = port - 1;
            ranges.push(if end == start {
                start.to_string()
            } else {
                format!("{start}-{end}")
            });
        }
        start = port + 1;
    }
    ranges.join(",")
}

/// Ajoute une règle entrante de blocage depuis `remote`, tous profils, tous programmes.
/// `local_ports` : `None` pour un protocole sans ports (ICMP).
fn add_block_rule(
    rules: &INetFwRules,
    name: &str,
    protocol: i32,
    local_ports: Option<&str>,
    remote: &str,
) -> Result<()> {
    // SAFETY: création COM standard d'un objet in-process.
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .ctx("Création de la règle de pare-feu")?;
    // SAFETY: appels COM sur une interface valide ; les BSTR vivent pendant chaque appel.
    // Le protocole est fixé avant les ports, comme l'exige le pare-feu.
    (|| unsafe {
        rule.SetName(&BSTR::from(name))?;
        rule.SetDescription(&BSTR::from("Partage Wi-Fi : isolation des appareils"))?;
        rule.SetProtocol(protocol)?;
        if let Some(ports) = local_ports {
            rule.SetLocalPorts(&BSTR::from(ports))?;
        }
        rule.SetRemoteAddresses(&BSTR::from(remote))?;
        rule.SetDirection(NET_FW_RULE_DIR_IN)?;
        rule.SetAction(NET_FW_ACTION_BLOCK)?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
        rule.SetEnabled(VARIANT_TRUE)
    })()
    .ctx("Configuration de la règle d'isolation")?;
    // SAFETY: appel COM sur une interface valide.
    unsafe { rules.Add(&rule) }.ctx("Ajout de la règle d'isolation")
}

/// Active ou retire l'isolation : règles entrantes de **blocage** depuis `remote` (CIDR du point
/// d'accès), tous profils, nommées `axios-isolation-tcp|udp|icmp` : TCP ports locaux sauf
/// `keep_tcp` (le proxy), UDP sauf 53 (DNS) et 67 (DHCP), ICMPv4. Idempotent.
pub fn set_isolation(enabled: bool, remote: &str, keep_tcp: u16) -> Result<()> {
    let rules = rules()?;
    let names = [ISOLATION_TCP, ISOLATION_UDP, ISOLATION_ICMP];
    let remove_all = |rules: &INetFwRules| -> Result<()> {
        names
            .iter()
            .try_for_each(|n| delete_all(rules, &BSTR::from(*n)))
    };
    remove_all(&rules)?;
    if !enabled {
        log::info!("isolation des appareils retirée du pare-feu");
        return Ok(());
    }

    let tcp_ports = ports_except(&[keep_tcp]);
    let udp_ports = ports_except(&ISOLATION_UDP_KEEP);
    let added = add_block_rule(
        &rules,
        ISOLATION_TCP,
        NET_FW_IP_PROTOCOL_TCP.0,
        Some(&tcp_ports),
        remote,
    )
    .and_then(|()| {
        add_block_rule(
            &rules,
            ISOLATION_UDP,
            NET_FW_IP_PROTOCOL_UDP.0,
            Some(&udp_ports),
            remote,
        )
    })
    .and_then(|()| add_block_rule(&rules, ISOLATION_ICMP, IP_PROTOCOL_ICMPV4, None, remote));
    if let Err(e) = added {
        // Pas d'isolation partielle : on retire ce qui a pu être créé.
        if let Err(cleanup) = remove_all(&rules) {
            log::warn!("nettoyage des règles d'isolation impossible : {cleanup}");
        }
        return Err(e);
    }
    log::info!(
        "isolation des appareils active depuis {remote} (TCP sauf {keep_tcp}, UDP sauf 53/67, ICMP)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges_except() {
        assert_eq!(ports_except(&[8229]), "1-8228,8230-65535");
        assert_eq!(ports_except(&[53, 67]), "1-52,54-66,68-65535");
        assert_eq!(ports_except(&[67, 53, 53]), "1-52,54-66,68-65535");
        assert_eq!(ports_except(&[]), "1-65535");
        assert_eq!(ports_except(&[0]), "1-65535");
        assert_eq!(ports_except(&[1]), "2-65535");
        assert_eq!(ports_except(&[65535]), "1-65534");
        assert_eq!(ports_except(&[1, 65535]), "2-65534");
        assert_eq!(ports_except(&[2]), "1,3-65535");
        assert_eq!(ports_except(&[10, 12]), "1-9,11,13-65535");
        assert_eq!(ports_except(&[10, 11]), "1-9,12-65535");
        assert_eq!(ports_except(&[65534]), "1-65533,65535");
        let all: Vec<u16> = (1..=u16::MAX).collect();
        assert_eq!(ports_except(&all), "");
    }

    #[test]
    #[ignore = "modifie le pare-feu réel (admin requis)"]
    fn isolation_roundtrip() {
        set_isolation(true, "192.168.137.0/24", 8229).unwrap();
        set_isolation(true, "192.168.137.0/24", 8229).unwrap();
        set_isolation(false, "192.168.137.0/24", 8229).unwrap();
    }

    #[test]
    #[ignore = "modifie le pare-feu réel (admin requis)"]
    fn rule_roundtrip() {
        let exe = std::env::current_exe().unwrap();
        ensure_rule("PartageWiFi-Test", &exe, 8229, "192.168.137.0/24").unwrap();
        ensure_rule("PartageWiFi-Test", &exe, 8229, "192.168.137.0/24").unwrap();
        remove_rule("PartageWiFi-Test").unwrap();
    }
}
