use std::time::Instant;

pub struct QueryTimer {
    enabled: bool,
    total_time: u64,
    count: u64,
    start_time: Option<Instant>,
}

impl QueryTimer {
    pub const fn new(enabled: bool) -> Self {
        Self {
            enabled,
            total_time: 0,
            count: 0,
            start_time: None,
        }
    }

    pub fn start(&mut self) {
        if self.enabled {
            self.start_time = Some(Instant::now());
        }
    }

    pub fn stop(&mut self) {
        if let (true, Some(start)) = (self.enabled, self.start_time.take()) {
            let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(0);
            self.total_time += elapsed;
            self.count += 1;
        }
    }

    pub const fn average(&self) -> Option<u64> {
        if self.enabled && self.count > 0 {
            Some(self.total_time / self.count)
        } else {
            None
        }
    }
}
