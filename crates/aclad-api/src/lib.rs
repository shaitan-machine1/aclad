//! Synchronous public D-Bus client and protocol types for aclad.
use dbus::blocking::{Connection, Proxy};
use std::time::Duration;

pub const BUS_NAME: &str = "org.decoupling.aclad1";
pub const OBJECT_PATH: &str = "/org/decoupling/aclad1";
pub const INTERFACE_NAME: &str = "org.decoupling.aclad1.Manager";
pub type GrantDescription = (String, u32, String);

pub struct Client {
    connection: Connection,
    timeout: Duration,
}
impl Client {
    pub fn system(timeout: Duration) -> Result<Self, dbus::Error> {
        Ok(Self {
            connection: Connection::new_system()?,
            timeout,
        })
    }
    pub fn session(timeout: Duration) -> Result<Self, dbus::Error> {
        Ok(Self {
            connection: Connection::new_session()?,
            timeout,
        })
    }
    fn proxy(&self) -> Proxy<'static, &Connection> {
        self.connection
            .with_proxy(BUS_NAME, OBJECT_PATH, self.timeout)
    }
    pub fn list_grants(&self) -> Result<Vec<GrantDescription>, dbus::Error> {
        let (grants,): (Vec<GrantDescription>,) =
            self.proxy().method_call(INTERFACE_NAME, "ListGrants", ())?;
        Ok(grants)
    }
    pub fn grant(&self, sid: &str, uid: u32, seat: &str) -> Result<(), dbus::Error> {
        let _: () = self
            .proxy()
            .method_call(INTERFACE_NAME, "Grant", (sid, uid, seat))?;
        Ok(())
    }
    pub fn revoke(&self, sid: &str) -> Result<(), dbus::Error> {
        let _: () = self.proxy().method_call(INTERFACE_NAME, "Revoke", (sid,))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_names_are_stable() {
        assert_eq!(BUS_NAME, "org.decoupling.aclad1");
        assert_eq!(OBJECT_PATH, "/org/decoupling/aclad1");
        assert_eq!(INTERFACE_NAME, "org.decoupling.aclad1.Manager");
    }
}
