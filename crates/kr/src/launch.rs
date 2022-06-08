//! Configure our ssh agent to run as daemon on the user system

use crate::error::Error;
use askama::Template;
use nix::unistd::Uid;

#[derive(Debug, Clone)]
pub struct Daemon {
    pub name: String,
    pub bin_name: String,
    pub bin_path: String,
}

impl Daemon {
    const BIN_NAME: &'static str = env!("CARGO_BIN_NAME");
    const NAME: &'static str = env!("CARGO_PKG_NAME");

    pub fn new() -> Result<Self, Error> {
        Ok(Daemon {
            bin_name: Self::BIN_NAME.to_string(),
            name: Self::NAME.to_string(),
            bin_path: std::env::current_exe()?.to_string_lossy().to_string(),
        })
    }

    pub fn install(self) -> Result<(), Error> {
        self.os_specific().install()
    }

    pub fn render(self) -> Result<String, Error> {
        Ok(self.os_specific().render()?)
    }

    #[cfg(target_os = "linux")]
    fn os_specific(self) -> SystemdService {
        return SystemdService::from(self);
    }

    #[cfg(target_os = "macos")]
    fn os_specific(self) -> LaunchAgent {
        return LaunchAgent::from(self);
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Template)]
#[template(path = "macos/launch_agent.plist", escape = "none")]
struct LaunchAgent {
    label: String,
    bin_name: String,
    bin_path: String,
}

#[cfg(target_os = "macos")]
impl From<Daemon> for LaunchAgent {
    fn from(d: Daemon) -> Self {
        Self {
            label: format!("com.akamai.{}", d.bin_name),
            bin_name: d.bin_name,
            bin_path: d.bin_path,
        }
    }
}
#[cfg(target_os = "macos")]
impl LaunchAgent {
    fn install(&self) -> Result<(), Error> {
        let dirs = directories::UserDirs::new().ok_or(Error::CannotCreateHomeDir)?;
        let path = dirs
            .home_dir()
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{}.plist", &self.label));

        if path.exists() {
            // first unload if already there
            let _ = std::process::Command::new("launchctl")
                .arg("unload")
                .arg("-w")
                .arg(&path)
                .output()?;
        }

        let contents = self.render()?;
        std::fs::write(&path, contents)?;

        // then reload
        let _ = std::process::Command::new("launchctl")
            .arg("load")
            .arg("-w")
            .arg(&path)
            .output()?;

        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Template)]
#[template(path = "linux/systemd.service", escape = "none")]
struct SystemdService {
    description: String,
    bin_path: String,
    bin_name: String,
    current_user: String,
}

#[cfg(target_os = "linux")]
impl From<Daemon> for SystemdService {
    fn from(d: Daemon) -> Self {
        Self {
            bin_name: d.bin_name,
            bin_path: d.bin_path,
            description: env!("CARGO_PKG_DESCRIPTION").to_string(),
            current_user: whoami::username(),
        }
    }
}

#[cfg(target_os = "linux")]
impl SystemdService {
    fn install(&self) -> Result<(), Error> {
        let dirs = directories::UserDirs::new().ok_or(Error::CannotCreateHomeDir)?;

        let path = dirs.home_dir().join(".config").join("systemd").join("user");
        std::fs::create_dir_all(&path)?;

        let service_name = format!("{}.service", &self.bin_name);

        let path_to_write = path.clone().join(&service_name);
        let contents = self.render()?;
        std::fs::write(path_to_write, contents)?;

        if Uid::effective().is_root() {

            let _= std::process::Command::new("systemctl")
            .arg("--now")
            .arg("enable")
            .arg(path.join(&service_name))
            .output()?;
        }

        else {
            let _ = std::process::Command::new("systemctl")
            .arg("--user")
            .arg("--now")
            .arg("enable")
            .arg(service_name)
            .output()?;
        }
        

        Ok(())
    }
}
