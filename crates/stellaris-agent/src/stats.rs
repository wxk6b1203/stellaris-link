//! Lightweight dataplane counters exposed via /v1/status.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Stats {
    pub acl_denied: AtomicU64,
    pub acl_rejected: AtomicU64,
    pub spoof_dropped: AtomicU64,
    pub frag_reassembled: AtomicU64,
    pub frag_dropped: AtomicU64,
    pub qos_rate_limited: AtomicU64,
    pub queue_dropped: AtomicU64,
    pub delivered: AtomicU64,
    pub forwarded: AtomicU64,
}

impl Stats {
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "acl_denied": self.acl_denied.load(Ordering::Relaxed),
            "acl_rejected": self.acl_rejected.load(Ordering::Relaxed),
            "spoof_dropped": self.spoof_dropped.load(Ordering::Relaxed),
            "frag_reassembled": self.frag_reassembled.load(Ordering::Relaxed),
            "frag_dropped": self.frag_dropped.load(Ordering::Relaxed),
            "qos_rate_limited": self.qos_rate_limited.load(Ordering::Relaxed),
            "queue_dropped": self.queue_dropped.load(Ordering::Relaxed),
            "delivered": self.delivered.load(Ordering::Relaxed),
            "forwarded": self.forwarded.load(Ordering::Relaxed),
        })
    }
}
