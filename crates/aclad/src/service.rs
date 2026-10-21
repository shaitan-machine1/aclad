use crate::acl::AclBackend;
use crate::grant::{Grant, GrantStore, valid_sid};
use anyhow::Context;
use seat_udev::{Event, SeatDevice, SeatName};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

struct State {
    grants: BTreeMap<String, Grant>,
    devices: BTreeMap<std::path::PathBuf, SeatDevice>,
}

pub struct Service {
    state: Mutex<State>,
    store: Arc<dyn GrantStore>,
    acl: Arc<dyn AclBackend>,
}

impl Service {
    pub fn load(
        store: Arc<dyn GrantStore>,
        acl: Arc<dyn AclBackend>,
        devices: Vec<SeatDevice>,
    ) -> anyhow::Result<Self> {
        let grants = store.load()?;
        let devices = devices
            .into_iter()
            .map(|device| (device.syspath.clone(), device))
            .collect();
        let service = Self {
            state: Mutex::new(State { grants, devices }),
            store,
            acl,
        };
        service.recompute_all()?;
        Ok(service)
    }

    pub fn grant(&self, sid: &str, uid: u32, seat: SeatName) -> anyhow::Result<()> {
        anyhow::ensure!(valid_sid(sid), "invalid session id");
        let mut state = self.state.lock().unwrap();
        let grant = Grant { uid, seat };
        if let Some(existing) = state.grants.get(sid) {
            anyhow::ensure!(
                existing == &grant,
                "session id already has a different grant"
            );
            return Ok(());
        }
        state.grants.insert(sid.to_owned(), grant.clone());
        if let Err(error) = self.recompute_seat_locked(&state, &grant.seat) {
            state.grants.remove(sid);
            let _ = self.recompute_seat_locked(&state, &grant.seat);
            return Err(error);
        }
        if let Err(error) = self.store.put(sid, &grant) {
            state.grants.remove(sid);
            let _ = self.recompute_seat_locked(&state, &grant.seat);
            return Err(error).context("persist grant");
        }
        Ok(())
    }

    pub fn revoke(&self, sid: &str) -> anyhow::Result<()> {
        anyhow::ensure!(valid_sid(sid), "invalid session id");
        let mut state = self.state.lock().unwrap();
        let Some(grant) = state.grants.remove(sid) else {
            self.store.remove(sid)?;
            return Ok(());
        };
        if let Err(error) = self.recompute_seat_locked(&state, &grant.seat) {
            state.grants.insert(sid.to_owned(), grant);
            return Err(error);
        }
        if let Err(error) = self.store.remove(sid) {
            state.grants.insert(sid.to_owned(), grant.clone());
            let _ = self.recompute_seat_locked(&state, &grant.seat);
            return Err(error).context("remove persisted grant");
        }
        Ok(())
    }

    pub fn reconcile_sessions(&self, live: &BTreeSet<String>) -> anyhow::Result<()> {
        let stale: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .grants
            .keys()
            .filter(|sid| !live.contains(*sid))
            .cloned()
            .collect();
        for sid in stale {
            self.revoke(&sid)?;
        }
        Ok(())
    }

    pub fn handle_event(&self, event: Event) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        match event {
            Event::DeviceAdded(device) => {
                state.devices.insert(device.syspath.clone(), device.clone());
                if device.uaccess {
                    self.apply_device_locked(&state, &device)?;
                }
            }
            Event::DeviceRemoved(device) => {
                state.devices.remove(&device.syspath);
            }
            Event::DeviceMoved { device, from } => {
                state.devices.insert(device.syspath.clone(), device.clone());
                self.recompute_seat_locked(&state, &from)?;
                if device.uaccess {
                    self.apply_device_locked(&state, &device)?;
                }
            }
            Event::SeatAdded(_) | Event::SeatRemoved(_) => {}
        }
        Ok(())
    }

    pub fn grants(&self) -> BTreeMap<String, Grant> {
        self.state.lock().unwrap().grants.clone()
    }

    fn recompute_all(&self) -> anyhow::Result<()> {
        let state = self.state.lock().unwrap();
        for device in state.devices.values().filter(|device| device.uaccess) {
            self.apply_device_locked(&state, device)?;
        }
        self.apply_static_locked(&state)
    }

    fn recompute_seat_locked(&self, state: &State, seat: &SeatName) -> anyhow::Result<()> {
        for device in state
            .devices
            .values()
            .filter(|device| device.uaccess && &device.seat == seat)
        {
            self.apply_device_locked(state, device)?;
        }
        if seat == &SeatName::seat0() {
            self.apply_static_locked(state)?;
        }
        Ok(())
    }

    fn apply_device_locked(&self, state: &State, device: &SeatDevice) -> anyhow::Result<()> {
        let Some(path) = &device.devnode else {
            return Ok(());
        };
        let users = users_for_seat(state, &device.seat);
        self.acl
            .set_users(path, &users)
            .with_context(|| format!("update ACL on {}", path.display()))
    }

    fn apply_static_locked(&self, state: &State) -> anyhow::Result<()> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let users = users_for_seat(state, &SeatName::seat0());
        for path in self.acl.static_seat0_nodes()? {
            let metadata = std::fs::metadata(&path)?;
            let kind = metadata.file_type();
            if !kind.is_char_device() && !kind.is_block_device() {
                continue;
            }
            if state
                .devices
                .values()
                .any(|device| device.devnum == Some(metadata.rdev()))
            {
                continue;
            }
            self.acl
                .set_users(&path, &users)
                .with_context(|| format!("update ACL on static node {}", path.display()))?;
        }
        Ok(())
    }
}

fn users_for_seat(state: &State, seat: &SeatName) -> BTreeSet<u32> {
    state
        .grants
        .values()
        .filter(|grant| &grant.seat == seat)
        .map(|grant| grant.uid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::AclBackend;
    use crate::grant::GrantStore;
    use seat_udev::DeviceKind;
    use std::path::{Path, PathBuf};

    #[derive(Default)]
    struct MemoryStore(Mutex<BTreeMap<String, Grant>>);
    impl GrantStore for MemoryStore {
        fn load(&self) -> anyhow::Result<BTreeMap<String, Grant>> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn put(&self, sid: &str, grant: &Grant) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(sid.into(), grant.clone());
            Ok(())
        }
        fn remove(&self, sid: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(sid);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeAcl(Mutex<BTreeMap<PathBuf, BTreeSet<u32>>>);
    impl AclBackend for FakeAcl {
        fn set_users(&self, path: &Path, users: &BTreeSet<u32>) -> anyhow::Result<()> {
            self.0.lock().unwrap().insert(path.into(), users.clone());
            Ok(())
        }
        fn static_seat0_nodes(&self) -> anyhow::Result<Vec<PathBuf>> {
            Ok(Vec::new())
        }
    }

    fn device(path: &str, seat: &str) -> SeatDevice {
        SeatDevice {
            syspath: format!("/sys{path}").into(),
            devnode: Some(path.into()),
            devnum: None,
            seat: SeatName::parse(seat).unwrap(),
            kind: DeviceKind::Other,
            uaccess: true,
            master_of_seat: false,
        }
    }
    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "1123456789abcdef0123456789abcdef";

    #[test]
    fn recomputes_exact_union_and_conflicts_are_rejected() {
        let store = Arc::new(MemoryStore::default());
        let acl = Arc::new(FakeAcl::default());
        let service =
            Service::load(store.clone(), acl.clone(), vec![device("/dev/a", "seat0")]).unwrap();
        service.grant(A, 1000, SeatName::seat0()).unwrap();
        service.grant(B, 1001, SeatName::seat0()).unwrap();
        assert_eq!(
            acl.0.lock().unwrap()[Path::new("/dev/a")],
            BTreeSet::from([1000, 1001])
        );
        assert!(service.grant(A, 2000, SeatName::seat0()).is_err());
        service.revoke(A).unwrap();
        assert_eq!(
            acl.0.lock().unwrap()[Path::new("/dev/a")],
            BTreeSet::from([1001])
        );
    }

    #[test]
    fn grant_inventory_is_sorted_by_session_id() {
        let service = Service::load(
            Arc::new(MemoryStore::default()),
            Arc::new(FakeAcl::default()),
            vec![],
        )
        .unwrap();
        service.grant(B, 1001, SeatName::seat0()).unwrap();
        service.grant(A, 1000, SeatName::seat0()).unwrap();
        assert_eq!(
            service.grants().into_keys().collect::<Vec<_>>(),
            vec![A.to_owned(), B.to_owned()]
        );
    }

    #[test]
    fn hotplug_uses_current_grants_and_session_reconcile_revokes() {
        let acl = Arc::new(FakeAcl::default());
        let service = Service::load(Arc::new(MemoryStore::default()), acl.clone(), vec![]).unwrap();
        service
            .grant(A, 1000, SeatName::parse("seat1").unwrap())
            .unwrap();
        service
            .handle_event(Event::DeviceAdded(device("/dev/hot", "seat1")))
            .unwrap();
        assert_eq!(
            acl.0.lock().unwrap()[Path::new("/dev/hot")],
            BTreeSet::from([1000])
        );
        service.reconcile_sessions(&BTreeSet::new()).unwrap();
        assert_eq!(
            acl.0.lock().unwrap()[Path::new("/dev/hot")],
            BTreeSet::new()
        );
    }
}
