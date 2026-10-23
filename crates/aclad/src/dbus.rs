use crate::service::Service;
pub use aclad_api::{BUS_NAME, GrantDescription, INTERFACE_NAME, OBJECT_PATH};
use seat_udev::SeatName;
use std::sync::Arc;
use zbus::Connection;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::BusName;

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.decoupling.aclad1.Error")]
pub enum ManagerError {
    AccessDenied(String),
    InvalidArgument(String),
    Conflict(String),
    BackendFailure(String),
}

pub struct Manager {
    service: Arc<Service>,
}

impl Manager {
    pub fn new(service: Arc<Service>) -> Self {
        Self { service }
    }
}

#[zbus::interface(name = "org.decoupling.aclad1.Manager")]
impl Manager {
    async fn grant(
        &self,
        sid: String,
        uid: u32,
        seat: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), ManagerError> {
        require_root(caller_uid(connection, &header).await?)?;
        let seat = SeatName::parse(seat)
            .map_err(|error| ManagerError::InvalidArgument(error.to_string()))?;
        self.service.grant(&sid, uid, seat).map_err(map_error)
    }

    async fn revoke(
        &self,
        sid: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), ManagerError> {
        require_root(caller_uid(connection, &header).await?)?;
        self.service.revoke(&sid).map_err(map_error)
    }

    async fn list_grants(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<Vec<GrantDescription>, ManagerError> {
        require_root(caller_uid(connection, &header).await?)?;
        Ok(self
            .service
            .grants()
            .into_iter()
            .map(|(sid, grant)| (sid, grant.uid, grant.seat.to_string()))
            .collect())
    }
}

fn map_error(error: anyhow::Error) -> ManagerError {
    let message = error.to_string();
    if message.contains("different grant") {
        ManagerError::Conflict(message)
    } else if message.contains("invalid session") {
        ManagerError::InvalidArgument(message)
    } else {
        ManagerError::BackendFailure(message)
    }
}

async fn caller_uid(
    connection: &Connection,
    header: &Header<'_>,
) -> Result<Option<u32>, ManagerError> {
    let sender = header
        .sender()
        .ok_or_else(|| ManagerError::AccessDenied("message has no sender".into()))?;
    let proxy = fdo::DBusProxy::new(connection)
        .await
        .map_err(|error| ManagerError::BackendFailure(error.to_string()))?;
    proxy
        .get_connection_credentials(BusName::from(sender.clone()))
        .await
        .map(|credentials| credentials.unix_user_id())
        .map_err(|error| ManagerError::BackendFailure(error.to_string()))
}

fn require_root(uid: Option<u32>) -> Result<(), ManagerError> {
    if uid == Some(0) {
        Ok(())
    } else {
        Err(ManagerError::AccessDenied(
            "ACL administration is root-only".into(),
        ))
    }
}
