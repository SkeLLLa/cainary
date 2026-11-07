//! A minimal freedesktop Secret Service client (`org.freedesktop.secrets`), hand-written on
//! zbus so no GTK, glib or libsecret comes in. Design and error mapping: docs/design/secret-store.md.
//!
//! The session is always `plain`: the secret crosses the session bus unencrypted. That keeps
//! the client small, and the bus is only readable by this user and the bus daemon. It gives
//! **no protection against other programs running as this user**, who can read the same item
//! from the same service. Say so wherever the UI offers to store a secret.
//!
//! Unlocking can show a prompt. [`Interaction::Never`] never unlocks anything, so startup code
//! can ask without popping a dialog; only an explicit user action should use
//! [`Interaction::Allowed`]. [`SecretService::put`] and [`SecretService::delete`] have no such
//! switch because they are only ever the result of a user action: they unlock the default
//! collection when needed.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};
use std::time::Duration;

use futures_lite::{StreamExt, future};
use serde::{Deserialize, Serialize};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Type, Value};

/// The well-known name of the service.
pub const DEFAULT_DEST: &str = "org.freedesktop.secrets";

/// Reserved item names. The `/v1` is the format of the stored bytes.
pub const RULES_KEY: &str = "rules-key/v1";
pub const PROXY_CA_KEY: &str = "proxy-ca-key/v1";

/// `xdg:schema` of every item we store.
pub const SCHEMA: &str = "ua.SkeLLLa.cAInary.Secret";

/// How long a prompt may stay open before we give up on it: the user is expected to type a
/// password, so this is generous. Tests shorten it with [`SecretService::with_prompt_timeout`].
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the best-effort `Prompt.Dismiss` after a timeout may take.
const DISMISS_WAIT: Duration = Duration::from_secs(2);

const APPLICATION: &str = "cainary";
const CONTENT_TYPE: &str = "application/octet-stream";
const DEFAULT_ALIAS: &str = "default";
/// The null object path: "no prompt needed", or "no such alias".
const NONE_PATH: &str = "/";

const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

/// Whether a locked collection may be unlocked, which can prompt the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interaction {
    /// Never unlock; a locked item is [`SecretError::Locked`].
    Never,
    /// Unlock, following a prompt if the service returns one.
    Allowed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// No service on the bus, or it has no default collection. Nothing can be stored.
    Unavailable(String),
    /// The item is locked and wasn't (or couldn't be) unlocked: [`Interaction::Never`], or the
    /// user dismissed the prompt.
    Locked,
    /// The service answered with something this client doesn't understand.
    Malformed(String),
    /// Any other bus or service failure.
    Bus(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(why) => write!(f, "secret service unavailable: {why}"),
            Self::Locked => f.write_str("the keyring is locked"),
            Self::Malformed(why) => write!(f, "unexpected secret service reply: {why}"),
            Self::Bus(why) => write!(f, "secret service error: {why}"),
        }
    }
}

impl std::error::Error for SecretError {}

impl From<zbus::Error> for SecretError {
    fn from(e: zbus::Error) -> Self {
        use zbus::Error::{FDO, InvalidReply, MethodError, Variant};
        const NO_OWNER: [&str; 2] = [
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "org.freedesktop.DBus.Error.NameHasNoOwner",
        ];
        match &e {
            MethodError(name, ..) if NO_OWNER.contains(&name.as_str()) => {
                Self::Unavailable("no secret service on the bus".into())
            }
            MethodError(name, ..) if name.as_str() == "org.freedesktop.Secret.Error.IsLocked" => {
                Self::Locked
            }
            FDO(fdo)
                if matches!(
                    **fdo,
                    zbus::fdo::Error::ServiceUnknown(_) | zbus::fdo::Error::NameHasNoOwner(_)
                ) =>
            {
                Self::Unavailable("no secret service on the bus".into())
            }
            InvalidReply | Variant(_) => Self::Malformed(e.to_string()),
            _ => Self::Bus(e.to_string()),
        }
    }
}

impl From<zbus::fdo::Error> for SecretError {
    fn from(e: zbus::fdo::Error) -> Self {
        zbus::Error::from(e).into()
    }
}

/// Secret bytes. Zeroed when dropped; never printed.
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<{} bytes>)", self.bytes.len())
    }
}

/// Overwrites `buf` with zeros in a way the optimizer may not drop.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// The `(oayays)` struct of the specification. Our copy of the value is wiped on drop; the
/// marshalling buffers inside zbus are not ours to wipe.
#[derive(Serialize, Deserialize, Type)]
struct Wire {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

impl Drop for Wire {
    fn drop(&mut self) {
        wipe(&mut self.value);
    }
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Service")]
trait Service {
    fn open_session(
        &self,
        algorithm: &str,
        input: &Value<'_>,
    ) -> zbus::Result<(OwnedValue, OwnedObjectPath)>;

    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    fn unlock(
        &self,
        objects: &[ObjectPath<'_>],
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Session")]
trait Session {
    fn close(&self) -> zbus::Result<()>;
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Collection")]
trait Collection {
    fn search_items(&self, attributes: &HashMap<&str, &str>) -> zbus::Result<Vec<OwnedObjectPath>>;

    fn create_item(
        &self,
        properties: HashMap<&str, Value<'_>>,
        secret: &Wire,
        replace: bool,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Item")]
trait Item {
    fn get_secret(&self, session: &ObjectPath<'_>) -> zbus::Result<Wire>;

    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;
}

#[zbus::proxy(interface = "org.freedesktop.Secret.Prompt")]
trait Prompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;

    fn dismiss(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn completed(&self, dismissed: bool, result: OwnedValue) -> zbus::Result<()>;
}

/// A client of one Secret Service. Cheap: it holds the connection and the name, and opens a
/// short plain session per call.
#[derive(Clone)]
pub struct SecretService {
    conn: zbus::Connection,
    dest: String,
    prompt_timeout: Duration,
}

impl SecretService {
    /// Talks to the service named `dest` on `conn`; [`DEFAULT_DEST`] outside tests. Nothing
    /// is sent until the first call.
    pub fn connect(conn: zbus::Connection, dest: &str) -> Self {
        Self {
            conn,
            dest: dest.into(),
            prompt_timeout: PROMPT_TIMEOUT,
        }
    }

    /// Overrides how long a prompt may stay open ([`PROMPT_TIMEOUT`]).
    pub fn with_prompt_timeout(mut self, timeout: Duration) -> Self {
        self.prompt_timeout = timeout;
        self
    }

    pub fn connect_default(conn: zbus::Connection) -> Self {
        Self::connect(conn, DEFAULT_DEST)
    }

    /// The stored secret, `None` when there is none.
    pub async fn get(
        &self,
        item: &str,
        interaction: Interaction,
    ) -> Result<Option<Secret>, SecretError> {
        let open = self.open(item).await?;
        let result = open.get(interaction).await;
        open.close().await;
        result
    }

    /// Stores `bytes` under `item`, replacing what was there. `label` is what keyring UIs
    /// show; it must not contain secret material.
    pub async fn put(&self, item: &str, label: &str, bytes: &[u8]) -> Result<(), SecretError> {
        let open = self.open(item).await?;
        let result = open.put(label, bytes).await;
        open.close().await;
        result
    }

    /// Removes `item`. Removing what isn't there is fine.
    pub async fn delete(&self, item: &str) -> Result<(), SecretError> {
        let open = self.open(item).await?;
        let result = open.delete().await;
        open.close().await;
        result
    }

    async fn open(&self, item: &str) -> Result<Open, SecretError> {
        if item.is_empty() {
            return Err(SecretError::Malformed("empty item name".into()));
        }
        let service = ServiceProxy::builder(&self.conn)
            .destination(self.dest.clone())?
            .path("/org/freedesktop/secrets")?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await?;
        let collection = service.read_alias(DEFAULT_ALIAS).await?;
        if collection.as_str() == NONE_PATH {
            return Err(SecretError::Unavailable("no default collection".into()));
        }
        // The only algorithm this client speaks, see the module docs.
        let (_, session) = service.open_session("plain", &Value::from("")).await?;
        if session.as_str() == NONE_PATH {
            return Err(SecretError::Malformed("no session path".into()));
        }
        Ok(Open {
            conn: self.conn.clone(),
            dest: self.dest.clone(),
            prompt_timeout: self.prompt_timeout,
            service,
            collection,
            session,
            attributes: attributes(item),
        })
    }
}

/// Exactly these attributes, nothing derived from the secret.
fn attributes(item: &str) -> Vec<(&'static str, String)> {
    vec![
        ("xdg:schema", SCHEMA.into()),
        ("application", APPLICATION.into()),
        ("item", item.into()),
    ]
}

/// One call's state: the default collection and the plain session.
struct Open {
    conn: zbus::Connection,
    dest: String,
    prompt_timeout: Duration,
    service: ServiceProxy<'static>,
    collection: OwnedObjectPath,
    session: OwnedObjectPath,
    attributes: Vec<(&'static str, String)>,
}

impl Open {
    async fn collection(&self) -> Result<CollectionProxy<'static>, SecretError> {
        Ok(CollectionProxy::builder(&self.conn)
            .destination(self.dest.clone())?
            .path(self.collection.clone())?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await?)
    }

    async fn item(&self, path: OwnedObjectPath) -> Result<ItemProxy<'static>, SecretError> {
        Ok(ItemProxy::builder(&self.conn)
            .destination(self.dest.clone())?
            .path(path)?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await?)
    }

    /// Best effort: the service drops sessions when we disconnect anyway.
    async fn close(&self) {
        let Ok(builder) = SessionProxy::builder(&self.conn).destination(self.dest.clone()) else {
            return;
        };
        let Ok(builder) = builder.path(self.session.clone()) else {
            return;
        };
        if let Ok(session) = builder.build().await {
            let _ = session.close().await;
        }
    }

    /// The first item with our attributes.
    async fn find(&self) -> Result<Option<OwnedObjectPath>, SecretError> {
        let attrs: HashMap<&str, &str> = self
            .attributes
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();
        let found = self.collection().await?.search_items(&attrs).await?;
        Ok(found.into_iter().next())
    }

    async fn get(&self, interaction: Interaction) -> Result<Option<Secret>, SecretError> {
        let Some(path) = self.find().await? else {
            return Ok(None);
        };
        let item = self.item(path).await?;
        if item.locked().await? || self.collection().await?.locked().await? {
            if interaction == Interaction::Never {
                return Err(SecretError::Locked);
            }
            // Only what is locked: an item can be locked inside an unlocked collection.
            let mut locked = Vec::new();
            if item.locked().await? {
                locked.push(item.inner().path().to_owned());
            }
            if self.collection().await?.locked().await? {
                locked.push(self.collection.as_ref().to_owned());
            }
            self.unlock(&locked).await?;
            if item.locked().await? {
                return Err(SecretError::Locked);
            }
        }
        let mut wire = item.get_secret(&self.session.as_ref()).await?;
        Ok(Some(Secret::new(std::mem::take(&mut wire.value))))
    }

    async fn put(&self, label: &str, bytes: &[u8]) -> Result<(), SecretError> {
        let collection = self.collection().await?;
        if collection.locked().await? {
            self.unlock(&[self.collection.as_ref().to_owned()]).await?;
        }
        let attributes: HashMap<String, String> = self
            .attributes
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
        let mut properties = HashMap::new();
        properties.insert(ITEM_LABEL, Value::from(label));
        properties.insert(ITEM_ATTRIBUTES, Value::from(attributes));
        let wire = Wire {
            session: self.session.clone(),
            parameters: Vec::new(),
            value: bytes.to_vec(),
            content_type: CONTENT_TYPE.into(),
        };
        let (_, prompt) = collection.create_item(properties, &wire, true).await?;
        if prompt.as_str() != NONE_PATH && self.prompt(prompt).await? {
            return Err(SecretError::Locked);
        }
        Ok(())
    }

    async fn delete(&self) -> Result<(), SecretError> {
        let Some(path) = self.find().await? else {
            return Ok(());
        };
        if self.collection().await?.locked().await? {
            self.unlock(&[self.collection.as_ref().to_owned()]).await?;
        }
        let prompt = self.item(path).await?.delete().await?;
        if prompt.as_str() != NONE_PATH && self.prompt(prompt).await? {
            return Err(SecretError::Locked);
        }
        Ok(())
    }

    /// Unlocks `objects`, following the prompt. A dismissed prompt is `Locked`.
    async fn unlock(&self, objects: &[ObjectPath<'_>]) -> Result<(), SecretError> {
        let (_, prompt) = self.service.unlock(objects).await?;
        if prompt.as_str() != NONE_PATH && self.prompt(prompt).await? {
            return Err(SecretError::Locked);
        }
        Ok(())
    }

    /// Runs a prompt; true when the user dismissed it. Gives up when the service goes away or
    /// `prompt_timeout` passes, so a stuck keyring can't hang the caller.
    async fn prompt(&self, path: OwnedObjectPath) -> Result<bool, SecretError> {
        enum Outcome {
            Done(bool),
            Gone,
            TimedOut,
        }
        let prompt = PromptProxy::builder(&self.conn)
            .destination(self.dest.clone())?
            .path(path)?
            .build()
            .await?;
        // Subscribe to both before calling: the signal may arrive before the method returns,
        // and zbus doesn't end a signal stream when the service's owner goes away.
        let mut completed = prompt.receive_completed().await?;
        let mut owner = zbus::fdo::DBusProxy::new(&self.conn)
            .await?
            .receive_name_owner_changed()
            .await?;
        let dest = self.dest.as_str();
        let done = async {
            prompt.prompt("").await?;
            match completed.next().await {
                Some(signal) => Ok(Outcome::Done(signal.args()?.dismissed)),
                None => Err(SecretError::Bus("connection closed during a prompt".into())),
            }
        };
        let gone = async {
            while let Some(signal) = owner.next().await {
                let args = signal.args()?;
                if args.name.as_str() == dest && args.new_owner.is_none() {
                    return Ok(Outcome::Gone);
                }
            }
            future::pending().await
        };
        let timeout = async {
            async_io::Timer::after(self.prompt_timeout).await;
            Ok(Outcome::TimedOut)
        };
        match future::or(done, future::or(gone, timeout)).await? {
            Outcome::Done(dismissed) => Ok(dismissed),
            Outcome::Gone => Err(SecretError::Unavailable("keyring service went away".into())),
            Outcome::TimedOut => {
                let dismiss = async {
                    let _ = prompt.dismiss().await;
                };
                let bound = async {
                    async_io::Timer::after(DISMISS_WAIT).await;
                };
                future::or(dismiss, bound).await;
                Err(SecretError::Bus("prompt timed out".into()))
            }
        }
    }
}
