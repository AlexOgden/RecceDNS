use std::{num::NonZeroUsize, thread};

/// Logical CPUs available to this process (respects cgroup quotas and affinity).
/// Falls back to 1 if the value cannot be determined.
#[must_use]
pub fn count() -> usize {
    thread::available_parallelism().map_or(1, NonZeroUsize::get)
}
