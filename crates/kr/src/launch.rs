//! Configure our ssh agent to run as daemon on the user system

use crate::error::Error;
use askama::Template;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Daemon {
    pub name: String,
    pub bin_name: String,
}

impl Daemon {
    const BIN_NAME: &'static str = env!("CARGO_BIN_NAME");
    const NAME: &'static str = env!("CARGO_PKG_NAME");

    pub fn new() -> Self {
        Daemon {
            bin_name: Self::BIN_NAME.to_string(),
            name: Self::NAME.to_string(),
        }
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
}

#[cfg(target_os = "macos")]
impl From<Daemon> for LaunchAgent {
    fn from(d: Daemon) -> Self {
        Self {
            label: format!("com.akamai.{}", d.bin_name),
            bin_name: d.bin_name,
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
        let contents = self.render()?;
        Ok(std::fs::write(path, contents)?)
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
            bin_path: std::env::current_exe()
                .expect("failed to get exe path")
                .to_string_lossy()
                .to_string(),
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

        let path = path.join(&service_name);
        let contents = self.render()?;
        std::fs::write(path, contents)?;

        let _ = std::process::Command::new("systemctl")
            .arg("--user")
            .arg("--now")
            .arg("enable")
            .arg(service_name)
            .output()?;

        Ok(())
    }
}
