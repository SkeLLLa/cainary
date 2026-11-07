//! The Secret Service client against a fake `org.freedesktop.secrets`, which needs a private
//! session bus (`dbus-run-session -- cargo test`); without one the tests skip.

mod common;
mod secret_fake;

use cainary_tray_dbus::secrets::{Interaction, PROXY_CA_KEY, RULES_KEY, SCHEMA};
use cainary_tray_dbus::secrets::{SecretError, SecretService};
use common::{block_on, session};
use secret_fake::{State, serve, unique_name, with_default};

/// A fake with `state`, and a client for it. `None` without a session bus.
async fn setup(state: State) -> Option<(zbus::Connection, secret_fake::Shared, SecretService)> {
    let server = session().await?;
    let name = unique_name();
    let shared = serve(&server, &name, state).await;
    let client = SecretService::connect(session().await?, &name);
    Some((server, shared, client))
}

#[test]
fn missing_is_none() {
    block_on(async {
        let Some((_server, _state, client)) = setup(with_default()).await else {
            return;
        };
        let got = client.get(RULES_KEY, Interaction::Never).await.unwrap();
        assert!(got.is_none());
    });
}

#[test]
fn put_get_roundtrip() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        let bytes = [0u8, 1, 2, 0xff, 0, 7];
        client
            .put(RULES_KEY, "cAInary rules key", &bytes)
            .await
            .unwrap();
        client
            .put(PROXY_CA_KEY, "cAInary proxy CA key", b"other")
            .await
            .unwrap();
        let got = client
            .get(RULES_KEY, Interaction::Never)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.as_bytes(), bytes);
        assert_eq!(format!("{got:?}"), "Secret(<6 bytes>)");
        // Replace, not duplicate.
        client
            .put(RULES_KEY, "cAInary rules key", b"v2")
            .await
            .unwrap();
        let got = client
            .get(RULES_KEY, Interaction::Never)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.as_bytes(), b"v2");
        let s = state.lock().unwrap();
        assert_eq!(s.items.len(), 2);
        assert!(
            s.items
                .values()
                .all(|i| i.content_type == "application/octet-stream")
        );
    });
}

#[test]
fn locked_without_interaction() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        client.put(RULES_KEY, "l", b"secret").await.unwrap();
        state.lock().unwrap().locked = true;
        let err = client.get(RULES_KEY, Interaction::Never).await.unwrap_err();
        assert_eq!(err, SecretError::Locked);
        let s = state.lock().unwrap();
        assert_eq!(s.unlock_calls, 0, "Never must not call Unlock");
        assert_eq!(s.prompt_calls, 0);
        assert_eq!(s.get_secret_calls, 0);
    });
}

#[test]
fn prompt_approved_unlocks() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        client.put(RULES_KEY, "l", b"secret").await.unwrap();
        {
            let mut s = state.lock().unwrap();
            s.locked = true;
            s.approve = true;
        }
        let got = client
            .get(RULES_KEY, Interaction::Allowed)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.as_bytes(), b"secret");
        assert_eq!(state.lock().unwrap().prompt_calls, 1);
    });
}

#[test]
fn no_service_unavailable() {
    block_on(async {
        let Some(conn) = session().await else {
            return;
        };
        let client = SecretService::connect(conn, &unique_name());
        let err = client.get(RULES_KEY, Interaction::Never).await.unwrap_err();
        assert!(matches!(err, SecretError::Unavailable(_)), "{err:?}");
    });
}

#[test]
fn no_default_collection_unavailable() {
    block_on(async {
        let Some((_server, state, client)) = setup(State::default()).await else {
            return;
        };
        let err = client.put(RULES_KEY, "l", b"x").await.unwrap_err();
        assert_eq!(
            err,
            SecretError::Unavailable("no default collection".into())
        );
        assert!(
            state.lock().unwrap().items.is_empty(),
            "never creates a collection or item"
        );
    });
}

#[test]
fn prompt_dismissed_locked() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        client.put(RULES_KEY, "l", b"secret").await.unwrap();
        state.lock().unwrap().locked = true; // approve stays false: the user dismisses
        let err = client
            .get(RULES_KEY, Interaction::Allowed)
            .await
            .unwrap_err();
        assert_eq!(err, SecretError::Locked);
        let s = state.lock().unwrap();
        assert_eq!(s.prompt_calls, 1);
        assert_eq!(s.get_secret_calls, 0);
    });
}

#[test]
fn attributes_never_hold_secret() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        let secret = b"hunter2-very-secret";
        client
            .put(RULES_KEY, "cAInary rules key", secret)
            .await
            .unwrap();
        let s = state.lock().unwrap();
        let item = s.items.values().next().unwrap();
        let want = [
            ("xdg:schema", SCHEMA),
            ("application", "cainary"),
            ("item", RULES_KEY),
        ];
        assert_eq!(item.attributes.len(), want.len());
        for (k, v) in want {
            assert_eq!(item.attributes.get(k).map(String::as_str), Some(v));
        }
        let text = String::from_utf8_lossy(secret).to_string();
        assert!(!item.label.contains(&text));
        assert!(item.attributes.values().all(|v| !v.contains(&text)));
    });
}

#[test]
fn plain_session_only() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        client.put(RULES_KEY, "l", b"x").await.unwrap();
        client.get(RULES_KEY, Interaction::Never).await.unwrap();
        client.delete(RULES_KEY).await.unwrap();
        let s = state.lock().unwrap();
        assert!(!s.sessions.is_empty());
        for (algorithm, input) in &s.sessions {
            assert_eq!((algorithm.as_str(), input.as_str()), ("plain", ""));
        }
    });
}

#[test]
fn delete_removes() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        client.put(RULES_KEY, "l", b"x").await.unwrap();
        client.put(PROXY_CA_KEY, "l", b"y").await.unwrap();
        client.delete(RULES_KEY).await.unwrap();
        assert!(
            client
                .get(RULES_KEY, Interaction::Never)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            client
                .get(PROXY_CA_KEY, Interaction::Never)
                .await
                .unwrap()
                .is_some()
        );
        client.delete(RULES_KEY).await.unwrap(); // already gone
        assert_eq!(state.lock().unwrap().items.len(), 1);
    });
}

const SHORT: std::time::Duration = std::time::Duration::from_millis(200);

#[test]
fn prompt_never_completes_times_out() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        client.put(RULES_KEY, "l", b"secret").await.unwrap();
        {
            let mut s = state.lock().unwrap();
            s.locked = true;
            s.hang = true;
        }
        let client = client.with_prompt_timeout(SHORT);
        let err = client
            .get(RULES_KEY, Interaction::Allowed)
            .await
            .unwrap_err();
        assert_eq!(err, SecretError::Bus("prompt timed out".into()));
        // Dismiss is best effort and sent after the timeout.
        assert_eq!(state.lock().unwrap().dismiss_calls, 1);
    });
}

#[test]
fn service_exits_during_prompt_unavailable() {
    block_on(async {
        let Some(server) = session().await else {
            return;
        };
        let name = unique_name();
        let state = serve(&server, &name, with_default()).await;
        let Some(conn) = session().await else {
            return;
        };
        // A long timeout: only the owner going away may end the wait.
        let client = SecretService::connect(conn, &name)
            .with_prompt_timeout(std::time::Duration::from_secs(30));
        client.put(RULES_KEY, "l", b"secret").await.unwrap();
        {
            let mut s = state.lock().unwrap();
            s.locked = true;
            s.hang = true;
        }
        let watcher = {
            let state = state.clone();
            let name = name.clone();
            std::thread::spawn(move || {
                while state.lock().unwrap().prompt_calls == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                block_on(server.release_name(name.as_str())).unwrap();
            })
        };
        let err = client
            .get(RULES_KEY, Interaction::Allowed)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            SecretError::Unavailable("keyring service went away".into())
        );
        watcher.join().unwrap();
    });
}

#[test]
fn locked_item_in_unlocked_collection_unlocks() {
    block_on(async {
        let Some((_server, state, client)) = setup(with_default()).await else {
            return;
        };
        client.put(RULES_KEY, "l", b"secret").await.unwrap();
        let id = *state.lock().unwrap().items.keys().next().unwrap();
        state.lock().unwrap().locked_items.insert(id);
        let err = client.get(RULES_KEY, Interaction::Never).await.unwrap_err();
        assert_eq!(err, SecretError::Locked);
        assert_eq!(state.lock().unwrap().unlock_calls, 0);
        let got = client
            .get(RULES_KEY, Interaction::Allowed)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.as_bytes(), b"secret");
        let s = state.lock().unwrap();
        assert_eq!(s.unlock_calls, 1);
        assert_eq!(s.prompt_calls, 0);
    });
}
