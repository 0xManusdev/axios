//! Sonde en lecture seule : affiche l'état du point d'accès et du réseau.

use pw_winsys::{autostart, elevation, hotspot, net};

fn main() {
    println!("admin       : {}", elevation::is_elevated());
    println!("autostart   : {}", autostart::is_enabled("PartageWiFi"));
    let gateway = net::ics_gateway();
    println!("passerelle  : {gateway}");
    let if_index = net::interface_index_for(gateway);
    println!("interface   : {if_index:?}");
    if let Some(idx) = if_index {
        for (ip, mac) in net::neighbors(idx) {
            println!("voisin      : {ip} {mac}");
        }
    }
    match hotspot::info() {
        Ok(i) => println!("point d'accès : {i:?}"),
        Err(e) => println!(
            "point d'accès : erreur : {e} ({:?})",
            std::error::Error::source(&e)
        ),
    }
    match hotspot::sources() {
        Ok(list) => {
            for s in list {
                println!("source      : {s:?}");
            }
        }
        Err(e) => println!("sources     : erreur : {e}"),
    }
    match hotspot::current_source() {
        Ok(s) => println!("partagée    : {s:?}"),
        Err(e) => println!("partagée    : erreur : {e}"),
    }
    match hotspot::clients() {
        Ok(c) => println!("clients     : {c:?}"),
        Err(e) => println!("clients     : erreur : {e}"),
    }
}
