use std::panic;
use tracing::error;

/// Replaces the default panic hook with one that emits a structured error event.
pub fn install_panic_hook() {
    panic::set_hook(Box::new(|panic_info| {
        if let Some(location) = panic_info.location() {
            error!(
                panic.file = location.file(),
                panic.line = location.line(),
                panic.column = location.column(),
                "process panicked; payload intentionally redacted"
            );
        } else {
            error!("process panicked; payload intentionally redacted");
        }
    }));
}
