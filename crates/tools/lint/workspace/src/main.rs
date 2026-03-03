use std::{
    error::Error,
    fmt,
    fmt::{Display, Formatter},
    fs,
};

use toml::Value;
use walkdir::WalkDir;

#[derive(Debug)]
struct WorkspaceError;

impl Error for WorkspaceError {}

impl Display for WorkspaceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Root Cargo.toml workspace members are inconsistent")
    }
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let root_cargo_toml_path = fs::read_to_string("Cargo.toml")?;
    let root_cargo_toml: Value = toml::from_str(root_cargo_toml_path.as_str())?;

    let mut members = root_cargo_toml["workspace"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<&str>>();

    let crates = WalkDir::new("crates")
        .follow_links(true)
        .into_iter()
        .filter_map(|error| error.ok())
        .filter_map(|dir_entry| {
            let file_name = dir_entry.file_name().to_str().unwrap();
            if file_name == "Cargo.toml" {
                let path = dir_entry.path();
                let parent = path.parent().unwrap();
                let dir_name = parent.to_str().unwrap().to_string();
                Some(dir_name)
            } else {
                None
            }
        })
        .collect::<Vec<String>>();

    let mut result = Ok(());

    for crate_ in crates.clone() {
        if !members.contains(&crate_.as_str()) {
            println!("Root Cargo.toml is missing member: {crate_}");
            result = Err(WorkspaceError.into());
        }
    }

    for member in members.clone() {
        if !crates.contains(&member.to_string()) {
            println!("Root Cargo.toml has unknown member: {member}");
            result = Err(WorkspaceError.into());
        }
    }

    for member in members.clone() {
        if members.iter().filter(|item| *item == &member).count() > 1 {
            println!("Root Cargo.toml has redundant member: {member}");
            result = Err(WorkspaceError.into());

            members = members
                .iter()
                .filter(|item| *item != &member)
                .copied()
                .collect::<Vec<&str>>();
        }
    }

    result
}
