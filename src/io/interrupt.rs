use anyhow::Result;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub fn initialize_interrupt_handler() -> Result<Arc<AtomicBool>> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupted_clone = Arc::clone(&interrupted);
    ctrlc::set_handler(move || {
        interrupted_clone.store(true, Ordering::SeqCst);
    })?;
    Ok(interrupted)
}
