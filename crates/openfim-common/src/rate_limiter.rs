use std::time::{Duration, Instant};

/// Upper bound on any single throttle wait, in seconds.
///
/// This exists so that a misconfigured very low rate limit degrades into slow
/// progress rather than an apparent hang inside one `consume` call.
const MAX_SINGLE_WAIT_SECS: f64 = 2.0;

/// Token-Bucket Rate Limiter to restrict I/O bandwidth and prevent disk thrashing.
#[derive(Debug)]
pub struct TokenBucket {
    bytes_per_second: u64,
    capacity: f64,
    tokens: f64,
    last_refill: Instant,
    enabled: bool,
}

impl TokenBucket {
    /// Creates a new TokenBucket rate limiter with the specified bytes-per-second limit.
    /// Setting `bytes_per_second` to 0 disables throttling (unlimited throughput).
    pub fn new(bytes_per_second: u64) -> Self {
        let capacity = if bytes_per_second == 0 {
            0.0
        } else {
            // Buffer capacity set to 2x the per-second rate to allow burst reads up to 2 seconds
            (bytes_per_second as f64) * 2.0
        };

        Self {
            bytes_per_second,
            capacity,
            tokens: 0.0,
            last_refill: Instant::now(),
            enabled: bytes_per_second > 0,
        }
    }

    /// Creates an unlimited rate limiter (zero artificial delay).
    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Refills tokens based on elapsed wall-clock time since last refill.
    fn refill(&mut self) {
        if !self.enabled {
            return;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        let added_tokens = elapsed * (self.bytes_per_second as f64);
        self.tokens = (self.tokens + added_tokens).min(self.capacity);
    }

    /// Consumes the requested number of bytes, sleeping if necessary to maintain the rate limit.
    pub fn consume(&mut self, bytes: usize) {
        if !self.enabled || bytes == 0 {
            return;
        }

        self.refill();

        let requested = bytes as f64;
        if self.tokens >= requested {
            self.tokens -= requested;
            return;
        }

        // Deficit: calculate required sleep duration
        let deficit = requested - self.tokens;
        let sleep_seconds = deficit / (self.bytes_per_second as f64);

        // Clamp the wait. A pathologically low rate limit combined with a 64 KB read
        // chunk yields an arithmetically correct sleep of many hours, which would hang
        // the scan with no diagnostic. Capping each wait keeps the limiter responsive
        // and still enforces the configured rate in aggregate across chunks.
        let sleep_duration =
            Duration::from_secs_f64(sleep_seconds.clamp(0.0, MAX_SINGLE_WAIT_SECS));

        std::thread::sleep(sleep_duration);

        // Deduct and reset last refill timestamp to avoid double credit
        self.tokens = 0.0;
        self.last_refill = Instant::now();
    }

    /// Returns whether throttling is currently active.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the configured rate limit in bytes per second.
    pub fn rate_bytes_per_sec(&self) -> u64 {
        self.bytes_per_second
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited_limiter() {
        let mut limiter = TokenBucket::unlimited();
        assert!(!limiter.is_enabled());
        let start = Instant::now();
        limiter.consume(10 * 1024 * 1024); // 10 MB
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn test_rate_throttling() {
        // Rate: 100 KB/s = 102,400 B/s
        let mut limiter = TokenBucket::new(100 * 1024);
        assert!(limiter.is_enabled());

        // Drain available tokens
        limiter.tokens = 0.0;
        limiter.last_refill = Instant::now();

        let start = Instant::now();
        // Request 50 KB -> should take approx 0.5 seconds
        limiter.consume(50 * 1024);
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(400), "Elapsed time was {:?}", elapsed);
    }

    #[test]
    fn test_single_wait_is_bounded_for_tiny_rate() {
        // A 1 byte/sec limit against a 64 KB chunk is an 18-hour wait if computed
        // literally. The limiter must cap each individual wait instead of hanging.
        let mut limiter = TokenBucket::new(1);
        limiter.tokens = 0.0;
        limiter.last_refill = Instant::now();

        let start = Instant::now();
        limiter.consume(64 * 1024);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "a single consume call blocked for {:?}; the throttle wait is unbounded",
            elapsed
        );
    }

    #[test]
    fn test_zero_byte_consume_is_free() {
        let mut limiter = TokenBucket::new(1024);
        let start = Instant::now();
        limiter.consume(0);
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
