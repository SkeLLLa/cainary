//! Single instance: the first claim wins the name, the second forwards to it.

mod common;

use cainary_tray_dbus::UiEvent;
use cainary_tray_dbus::instance::{self, Claim, Request};
use common::{block_on, next, session};

#[test]
fn a_second_instance_forwards_to_the_first() {
    block_on(async {
        let Some(first) = session().await else { return };
        let Some(second) = session().await else {
            return;
        };
        let (tx, rx) = async_channel::unbounded();
        let primary = match instance::claim(first, tx.clone()).await.unwrap() {
            Claim::Primary(conn) => conn,
            Claim::Secondary(_) => {
                eprintln!("skipped: a cainary-tray is already running on this bus");
                return;
            }
        };
        let Claim::Secondary(other) = instance::claim(second, tx).await.unwrap() else {
            panic!("the name was granted twice");
        };
        instance::forward(&other, &Request::ShowDetails("claude".into()))
            .await
            .unwrap();
        assert_eq!(
            next(&rx).await,
            UiEvent::ShowDetails {
                entry: Some("claude".into())
            }
        );
        instance::forward(&other, &Request::Activate).await.unwrap();
        assert_eq!(next(&rx).await, UiEvent::ShowDetails { entry: None });
        instance::forward(&other, &Request::Refresh).await.unwrap();
        assert_eq!(next(&rx).await, UiEvent::Refresh);
        instance::forward(&other, &Request::Quit).await.unwrap();
        assert_eq!(next(&rx).await, UiEvent::Quit);
        drop(primary);
    });
}
