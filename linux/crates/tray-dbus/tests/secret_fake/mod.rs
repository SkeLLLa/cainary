//! A fake `org.freedesktop.secrets` for the secret store tests: one default collection with
//! knobs for locking and prompts, and a record of what the client sent.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Type, Value};

pub const COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/p1";

#[derive(Debug, Clone)]
pub struct Stored {
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub value: Vec<u8>,
    pub content_type: String,
}

#[derive(Default)]
pub struct State {
    pub has_default: bool,
    pub locked: bool,
    /// What the unlock prompt does: true = the user approves.
    pub approve: bool,
    pub items: BTreeMap<u32, Stored>,
    next_id: u32,
    /// `(algorithm, input)` of every `OpenSession`.
    pub sessions: Vec<(String, String)>,
    pub unlock_calls: u32,
    pub prompt_calls: u32,
    pub get_secret_calls: u32,
}

pub type Shared = Arc<Mutex<State>>;

#[derive(Serialize, Deserialize, Type)]
struct Wire {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

use serde::{Deserialize, Serialize};

const NONE: &str = "/";

fn path(s: &str) -> OwnedObjectPath {
    ObjectPath::try_from(s).unwrap().into()
}

fn item_path(id: u32) -> String {
    format!("{COLLECTION}/{id}")
}

struct Service(Shared);

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn open_session(&self, algorithm: String, input: Value<'_>) -> (OwnedValue, OwnedObjectPath) {
        let input = String::try_from(input).unwrap_or_default();
        self.0.lock().unwrap().sessions.push((algorithm, input));
        (
            Value::from("").try_into().unwrap(),
            path("/org/freedesktop/secrets/session/s1"),
        )
    }

    fn read_alias(&self, name: String) -> OwnedObjectPath {
        if name == "default" && self.0.lock().unwrap().has_default {
            path(COLLECTION)
        } else {
            path(NONE)
        }
    }

    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let mut s = self.0.lock().unwrap();
        s.unlock_calls += 1;
        if s.locked {
            (vec![], path(PROMPT))
        } else {
            (objects, path(NONE))
        }
    }
}

struct Session;

#[zbus::interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    fn close(&self) {}
}

struct Prompt(Shared);

#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        _window_id: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        let approved = {
            let mut s = self.0.lock().unwrap();
            s.prompt_calls += 1;
            if s.approve {
                s.locked = false;
            }
            s.approve
        };
        let result: OwnedValue = if approved {
            Value::from(vec![path(COLLECTION)]).try_into().unwrap()
        } else {
            Value::from("").try_into().unwrap()
        };
        Self::completed(&emitter, !approved, result).await?;
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

struct Collection(Shared);

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        let s = self.0.lock().unwrap();
        s.items
            .iter()
            .filter(|(_, it)| {
                attributes
                    .iter()
                    .all(|(k, v)| it.attributes.get(k) == Some(v))
            })
            .map(|(id, _)| path(&item_path(*id)))
            .collect()
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Wire,
        replace: bool,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let attributes: HashMap<String, String> = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|v| HashMap::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let id = {
            let mut s = self.0.lock().unwrap();
            if s.locked {
                return Err(zbus::fdo::Error::Failed("collection is locked".into()));
            }
            let existing = s
                .items
                .iter()
                .find(|(_, it)| it.attributes == attributes)
                .map(|(id, _)| *id);
            let id = match existing {
                Some(id) if replace => id,
                _ => {
                    s.next_id += 1;
                    s.next_id
                }
            };
            s.items.insert(
                id,
                Stored {
                    label,
                    attributes,
                    value: secret.value,
                    content_type: secret.content_type,
                },
            );
            id
        };
        let p = item_path(id);
        // Re-registering an existing path is refused; that's fine.
        let _ = server.at(p.as_str(), Item(self.0.clone(), id)).await;
        Ok((path(&p), path(NONE)))
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.lock().unwrap().locked
    }
}

struct Item(Shared, u32);

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<Wire> {
        let mut s = self.0.lock().unwrap();
        s.get_secret_calls += 1;
        if s.locked {
            return Err(zbus::fdo::Error::Failed("item is locked".into()));
        }
        let it = s
            .items
            .get(&self.1)
            .ok_or_else(|| zbus::fdo::Error::Failed("no such item".into()))?;
        Ok(Wire {
            session,
            parameters: vec![],
            value: it.value.clone(),
            content_type: it.content_type.clone(),
        })
    }

    fn delete(&self) -> OwnedObjectPath {
        self.0.lock().unwrap().items.remove(&self.1);
        path(NONE)
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.lock().unwrap().locked
    }
}

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A destination name no other test (or real service) has.
pub fn unique_name() -> String {
    format!(
        "ua.SkeLLLa.cAInary.test.s{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Serves the fake on `conn` under `name`. Keep `conn` alive for as long as it should answer.
pub async fn serve(conn: &zbus::Connection, name: &str, state: State) -> Shared {
    let shared: Shared = Arc::new(Mutex::new(state));
    let objects = conn.object_server();
    objects
        .at("/org/freedesktop/secrets", Service(shared.clone()))
        .await
        .unwrap();
    objects
        .at("/org/freedesktop/secrets/session/s1", Session)
        .await
        .unwrap();
    objects.at(PROMPT, Prompt(shared.clone())).await.unwrap();
    objects
        .at(COLLECTION, Collection(shared.clone()))
        .await
        .unwrap();
    conn.request_name(name).await.unwrap();
    shared
}

/// Names a fake serves with a default collection.
pub fn with_default() -> State {
    State {
        has_default: true,
        ..State::default()
    }
}
