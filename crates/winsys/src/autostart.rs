//! Démarrage automatique via le Planificateur de tâches (COM `ITaskService`), sans `schtasks`.

use std::path::Path;

use windows::core::{BSTR, HRESULT};
use windows::Win32::Security::Authentication::Identity::{GetUserNameExW, NameSamCompatible};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_EXEC,
    TASK_CREATE_OR_UPDATE, TASK_INSTANCES_IGNORE_NEW, TASK_LOGON_INTERACTIVE_TOKEN,
    TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_LOGON,
};
use windows::Win32::System::Variant::VARIANT;

use crate::error::{Context, Result, WinsysError};

/// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)` : tâche absente.
const TASK_NOT_FOUND: HRESULT = HRESULT(0x8007_0002_u32 as i32);

fn connect() -> Result<(ITaskService, ITaskFolder)> {
    crate::com::ensure();
    // SAFETY: création COM standard d'un objet in-process.
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .ctx("Ouverture du Planificateur de tâches")?;
    let empty = VARIANT::default();
    // SAFETY: appels COM sur une interface valide ; connexion locale (paramètres vides).
    let folder = (|| unsafe {
        service.Connect(&empty, &empty, &empty, &empty)?;
        service.GetFolder(&BSTR::from("\\"))
    })()
    .ctx("Connexion au Planificateur de tâches")?;
    Ok((service, folder))
}

/// Utilisateur courant au format `DOMAINE\nom`.
fn current_user() -> Result<String> {
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` et `len` décrivent le même tampon, valide pendant l'appel.
    let ok = unsafe {
        GetUserNameExW(
            NameSamCompatible,
            Some(windows::core::PWSTR(buf.as_mut_ptr())),
            &mut len,
        )
    };
    if ok {
        return String::from_utf16(&buf[..len as usize])
            .map_err(|_| WinsysError::InvalidPath("nom d'utilisateur illisible".into()));
    }
    match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) => Ok(format!("{d}\\{u}")),
        _ => Err(WinsysError::Windows {
            context: "Lecture de l'utilisateur courant",
            source: windows::core::Error::from_thread(),
        }),
    }
}

/// `true` si la tâche `task_name` existe.
pub fn is_enabled(task_name: &str) -> bool {
    let Ok((_service, folder)) = connect() else {
        return false;
    };
    // SAFETY: appel COM sur une interface valide.
    unsafe { folder.GetTask(&BSTR::from(task_name)) }.is_ok()
}

/// Active (crée/remplace) ou désactive (supprime) la tâche « à l'ouverture de session ».
pub fn set(task_name: &str, enabled: bool, exe: &Path, args: &str) -> Result<()> {
    let (service, folder) = connect()?;
    let bname = BSTR::from(task_name);
    if !enabled {
        // SAFETY: appel COM sur une interface valide.
        return match unsafe { folder.DeleteTask(&bname, 0) } {
            Err(e) if e.code() != TASK_NOT_FOUND => Err(e).ctx("Suppression de la tâche planifiée"),
            _ => {
                log::info!("tâche planifiée « {task_name} » supprimée");
                Ok(())
            }
        };
    }

    let exe_str = exe
        .to_str()
        .ok_or_else(|| WinsysError::InvalidPath(exe.display().to_string()))?;
    let user = current_user()?;
    let buser = BSTR::from(user.as_str());

    // SAFETY: appels COM sur des interfaces valides, objets vivants pendant les appels.
    (|| unsafe {
        let def = service.NewTask(0)?;

        def.RegistrationInfo()?
            .SetDescription(&BSTR::from("Lance Partage Wi-Fi à l'ouverture de session"))?;

        let principal = def.Principal()?;
        principal.SetUserId(&buser)?;
        principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
        principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;

        let settings = def.Settings()?;
        settings.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;
        settings.SetDisallowStartIfOnBatteries(windows::Win32::Foundation::VARIANT_FALSE)?;
        settings.SetStopIfGoingOnBatteries(windows::Win32::Foundation::VARIANT_FALSE)?;
        settings.SetRunOnlyIfIdle(windows::Win32::Foundation::VARIANT_FALSE)?;
        settings.SetStartWhenAvailable(windows::Win32::Foundation::VARIANT_TRUE)?;
        settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)?;
        settings.SetExecutionTimeLimit(&BSTR::from("PT0S"))?;

        let trigger = def.Triggers()?.Create(TASK_TRIGGER_LOGON)?;
        let logon: ILogonTrigger = windows::core::Interface::cast(&trigger)?;
        logon.SetUserId(&buser)?;
        logon.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;

        let action = def.Actions()?.Create(TASK_ACTION_EXEC)?;
        let exec: IExecAction = windows::core::Interface::cast(&action)?;
        exec.SetPath(&BSTR::from(exe_str))?;
        exec.SetArguments(&BSTR::from(args))?;
        if let Some(dir) = exe.parent().and_then(Path::to_str) {
            exec.SetWorkingDirectory(&BSTR::from(dir))?;
        }

        folder
            .RegisterTaskDefinition(
                &bname,
                &def,
                TASK_CREATE_OR_UPDATE.0,
                &VARIANT::from(user.as_str()),
                &VARIANT::default(),
                TASK_LOGON_INTERACTIVE_TOKEN,
                &VARIANT::default(),
            )
            .map(drop)
    })()
    .ctx("Enregistrement de la tâche planifiée")?;
    log::info!("tâche planifiée « {task_name} » enregistrée pour {user}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_task_is_not_enabled() {
        assert!(!is_enabled("PartageWiFi-Inexistante-Test"));
    }

    #[test]
    #[ignore = "crée une tâche planifiée réelle (admin requis)"]
    fn task_roundtrip() {
        let exe = std::env::current_exe().unwrap();
        set("PartageWiFi-Test", true, &exe, "--minimized").unwrap();
        assert!(is_enabled("PartageWiFi-Test"));
        set("PartageWiFi-Test", false, &exe, "").unwrap();
        assert!(!is_enabled("PartageWiFi-Test"));
    }
}
