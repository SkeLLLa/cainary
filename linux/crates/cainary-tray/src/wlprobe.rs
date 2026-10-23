//! Whether the Wayland compositor offers `zwlr_layer_shell_v1`: one registry roundtrip on a
//! private connection. Any failure counts as "no".

use wayland_client::protocol::wl_registry;
use wayland_client::{Connection, Dispatch, QueueHandle};

const LAYER_SHELL: &str = "zwlr_layer_shell_v1";

#[derive(Default)]
struct Probe {
    found: bool,
}

impl Dispatch<wl_registry::WlRegistry, ()> for Probe {
    fn event(
        state: &mut Self,
        _: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global { interface, .. } = event
            && interface == LAYER_SHELL
        {
            state.found = true;
        }
    }
}

pub fn has_layer_shell() -> bool {
    let Ok(connection) = Connection::connect_to_env() else {
        return false;
    };
    let mut queue = connection.new_event_queue();
    let _registry = connection.display().get_registry(&queue.handle(), ());
    let mut probe = Probe::default();
    queue.roundtrip(&mut probe).is_ok() && probe.found
}
