//! Seau à jetons par client. Un modèle sur CPU sature vite : la limite protège
//! autant la disponibilité que le coût.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RateLimiter {
    pub fn check(&self, client: &str, per_minute: u32) -> bool {
        self.check_at(client, per_minute, Instant::now())
    }

    fn check_at(&self, client: &str, per_minute: u32, now: Instant) -> bool {
        let cap = per_minute as f64;
        let mut b = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let (tokens, last) = b.entry(client.to_string()).or_insert((cap, now));
        let refill = now.saturating_duration_since(*last).as_secs_f64() * cap / 60.0;
        *tokens = (*tokens + refill).min(cap);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rafale_puis_recharge() {
        let rl = RateLimiter::default();
        let t0 = Instant::now();
        assert!((0..3).all(|_| rl.check_at("a", 3, t0)));
        assert!(!rl.check_at("a", 3, t0));
        assert!(rl.check_at("b", 3, t0), "les clients sont indépendants");
        assert!(rl.check_at("a", 3, t0 + Duration::from_secs(20)));
    }
}
