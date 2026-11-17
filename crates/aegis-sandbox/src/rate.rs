//! Shared token-bucket-ish rate limiter (RoE `rate_limit_rps`).
//! Simple next-slot scheduler: each caller waits for its slot.

use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    delay: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    /// `rps <= 0` means unlimited — `wait` returns immediately.
    pub fn per_second(rps: f64) -> Self {
        let delay = if rps > 0.0 {
            Duration::from_secs_f64(1.0 / rps)
        } else {
            Duration::ZERO
        };
        Self {
            delay,
            next: Mutex::new(Instant::now()),
        }
    }

    pub async fn wait(&self) {
        if self.delay.is_zero() {
            return;
        }
        let wake = {
            let mut n = self.next.lock().unwrap();
            let now = Instant::now();
            let w = if *n > now { *n } else { now };
            *n = w + self.delay;
            w
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
    }
}
