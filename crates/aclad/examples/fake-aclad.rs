//! Hermetic D-Bus/PAM test service: real grant persistence and API with no
//! udev enumeration or host-device ACL mutation.
use aclad::acl::AclBackend;
use aclad::dbus::{BUS_NAME, Manager, OBJECT_PATH};
use aclad::grant::FsGrantStore;
use aclad::service::Service;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct NoDevices;

impl AclBackend for NoDevices {
    fn set_users(&self, _path: &Path, _users: &BTreeSet<u32>) -> anyhow::Result<()> {
        Ok(())
    }

    fn static_seat0_nodes(&self) -> anyhow::Result<Vec<PathBuf>> {
        Ok(Vec::new())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "fake aclad must run as root"
    );
    let grant_dir = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: fake-aclad GRANT_DIR"))?;
    let service = Arc::new(Service::load(
        Arc::new(FsGrantStore::new(grant_dir)),
        Arc::new(NoDevices),
        Vec::new(),
    )?);
    let connection = zbus::Connection::system().await?;
    connection
        .object_server()
        .at(OBJECT_PATH, Manager::new(service.clone()))
        .await?;
    connection.request_name(BUS_NAME).await?;
    let _ = aclad::sessiond::start(aclad::sessiond::Bus::System, service)?;
    std::future::pending::<()>().await;
    Ok(())
}
