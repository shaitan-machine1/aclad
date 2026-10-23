//! Typed public D-Bus protocol for aclad.

pub const BUS_NAME: &str = "org.decoupling.aclad1";
pub const OBJECT_PATH: &str = "/org/decoupling/aclad1";
pub const INTERFACE_NAME: &str = "org.decoupling.aclad1.Manager";

pub type GrantDescription = (String, u32, String);

#[zbus::proxy(
    interface = "org.decoupling.aclad1.Manager",
    default_service = "org.decoupling.aclad1",
    default_path = "/org/decoupling/aclad1"
)]
pub trait Manager {
    fn list_grants(&self) -> zbus::Result<Vec<GrantDescription>>;
    fn grant(&self, sid: &str, uid: u32, seat: &str) -> zbus::Result<()>;
    fn revoke(&self, sid: &str) -> zbus::Result<()>;
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
