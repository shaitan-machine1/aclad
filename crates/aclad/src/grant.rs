use anyhow::Context;
use seat_udev::SeatName;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub uid: u32,
    pub seat: SeatName,
}

pub fn valid_sid(sid: &str) -> bool {
    sid.len() == 32
        && sid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub trait GrantStore: Send + Sync {
    fn load(&self) -> anyhow::Result<BTreeMap<String, Grant>>;
    fn put(&self, sid: &str, grant: &Grant) -> anyhow::Result<()>;
    fn remove(&self, sid: &str) -> anyhow::Result<()>;
}

pub struct FsGrantStore {
    directory: PathBuf,
}

impl FsGrantStore {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn prepare(&self) -> anyhow::Result<()> {
        fs::create_dir_all(&self.directory)?;
        let metadata = fs::symlink_metadata(&self.directory)?;
        anyhow::ensure!(metadata.is_dir(), "grant path is not a directory");
        anyhow::ensure!(metadata.uid() == 0, "grant directory is not root-owned");
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn sync_directory(&self) -> anyhow::Result<()> {
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

impl GrantStore for FsGrantStore {
    fn load(&self) -> anyhow::Result<BTreeMap<String, Grant>> {
        self.prepare()?;
        let mut grants = BTreeMap::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let sid = entry.file_name().to_string_lossy().into_owned();
            if sid.starts_with('.') && sid.contains(".tmp-") {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            anyhow::ensure!(valid_sid(&sid), "invalid grant filename {sid:?}");
            let metadata = entry.metadata()?;
            anyhow::ensure!(metadata.is_file(), "grant {sid} is not a regular file");
            let grant: Grant = serde_json::from_reader(File::open(entry.path())?)
                .with_context(|| format!("parse grant {sid}"))?;
            grants.insert(sid, grant);
        }
        Ok(grants)
    }

    fn put(&self, sid: &str, grant: &Grant) -> anyhow::Result<()> {
        anyhow::ensure!(valid_sid(sid), "invalid session id");
        self.prepare()?;
        let temporary = self
            .directory
            .join(format!(".{sid}.tmp-{}", std::process::id()));
        let final_path = self.directory.join(sid);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let result = (|| {
            serde_json::to_writer(&mut file, grant)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temporary, &final_path)?;
            self.sync_directory()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn remove(&self, sid: &str) -> anyhow::Result<()> {
        anyhow::ensure!(valid_sid(sid), "invalid session id");
        self.prepare()?;
        match fs::remove_file(self.directory.join(sid)) {
            Ok(()) => self.sync_directory(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub fn default_grant_dir() -> &'static Path {
    Path::new("/run/aclad/grants")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_lower_hex_only() {
        assert!(valid_sid("0123456789abcdef0123456789abcdef"));
        for invalid in [
            "",
            "../x",
            "0123456789ABCDEF0123456789ABCDEF",
            "g123456789abcdef0123456789abcdef",
        ] {
            assert!(!valid_sid(invalid));
        }
    }
}
