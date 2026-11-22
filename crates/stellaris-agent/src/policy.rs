//! ACL and QoS policy evaluation (userspace, per packet).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use stellaris_types::{AclAction, AclConfig, AclDirection, NodeId, QosConfig, RouteAttributes};

use crate::wire::PacketInfo;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AclVerdict {
    Allow,
    Deny(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QosVerdict {
    Unmarked,
    Marked(u8),
    RateLimited,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub acl: AclConfig,
    #[serde(default)]
    pub qos: QosConfig,
}

impl PolicyFile {
    pub fn validate(&self) -> Result<(), String> {
        for rule in &self.acl.rules {
            if rule.name.trim().is_empty() {
                return Err("acl rule name must not be empty".into());
            }
        }
        for class in &self.qos.classes {
            if class.name.trim().is_empty() {
                return Err("qos class name must not be empty".into());
            }
            if class.dscp > 63 {
                return Err(format!("qos class {} dscp must be <= 63", class.name));
            }
            if class.rate_pps == Some(0) {
                return Err(format!("qos class {} rate_pps must be > 0", class.name));
            }
            if class.burst == Some(0) {
                return Err(format!("qos class {} burst must be > 0", class.name));
            }
            if class.rate_bps == Some(0) {
                return Err(format!("qos class {} rate_bps must be > 0", class.name));
            }
            if class.burst_bytes == Some(0) {
                return Err(format!("qos class {} burst_bytes must be > 0", class.name));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Debug)]
pub struct Policy {
    file: PolicyFile,
    acl_order: Vec<usize>,
    qos_order: Vec<usize>,
    buckets: Vec<Mutex<Bucket>>,
    byte_buckets: Vec<Mutex<Bucket>>,
    acl_hits: Vec<AtomicU64>,
}

impl Policy {
    pub fn from_config(acl: AclConfig, qos: QosConfig) -> Self {
        Self::from_file(PolicyFile { acl, qos })
    }

    pub fn from_file(file: PolicyFile) -> Self {
        let mut acl_order: Vec<usize> = (0..file.acl.rules.len()).collect();
        acl_order.sort_by(|a, b| {
            file.acl.rules[*b]
                .priority
                .cmp(&file.acl.rules[*a].priority)
                .then_with(|| a.cmp(b))
        });
        let mut qos_order: Vec<usize> = (0..file.qos.classes.len()).collect();
        qos_order.sort_by(|a, b| {
            file.qos.classes[*b]
                .priority
                .cmp(&file.qos.classes[*a].priority)
                .then_with(|| a.cmp(b))
        });
        let buckets = file
            .qos
            .classes
            .iter()
            .map(|class| {
                Mutex::new(Bucket {
                    tokens: class
                        .burst
                        .unwrap_or_else(|| class.rate_pps.unwrap_or(1))
                        .max(1) as f64,
                    last: Instant::now(),
                })
            })
            .collect();
        let byte_buckets = file
            .qos
            .classes
            .iter()
            .map(|class| {
                Mutex::new(Bucket {
                    tokens: class
                        .burst_bytes
                        .unwrap_or_else(|| class.rate_bps.unwrap_or(1))
                        .max(1) as f64,
                    last: Instant::now(),
                })
            })
            .collect();
        let acl_hits = (0..file.acl.rules.len())
            .map(|_| AtomicU64::new(0))
            .collect();
        Self {
            file,
            acl_order,
            qos_order,
            buckets,
            byte_buckets,
            acl_hits,
        }
    }

    pub fn file(&self) -> PolicyFile {
        self.file.clone()
    }

    pub fn acl_rules(&self) -> usize {
        self.file.acl.rules.len()
    }

    pub fn acl_hits(&self) -> Vec<(String, u64)> {
        self.file
            .acl
            .rules
            .iter()
            .zip(self.acl_hits.iter())
            .map(|(rule, hits)| (rule.name.clone(), hits.load(Ordering::Relaxed)))
            .collect()
    }

    pub fn qos_classes(&self) -> usize {
        self.file.qos.classes.len()
    }

    pub fn check(
        &self,
        direction: AclDirection,
        info: &PacketInfo,
        peer: Option<NodeId>,
        zone: Option<&str>,
    ) -> AclVerdict {
        for idx in &self.acl_order {
            let rule = &self.file.acl.rules[*idx];
            if rule.matches(
                direction,
                info.src,
                info.dst,
                info.protocol,
                info.src_port,
                info.dst_port,
                peer,
                zone,
            ) {
                self.acl_hits[*idx].fetch_add(1, Ordering::Relaxed);
                return match rule.action {
                    AclAction::Allow => AclVerdict::Allow,
                    AclAction::Deny => AclVerdict::Deny(rule.name.clone()),
                };
            }
        }
        match self.file.acl.default_action {
            AclAction::Allow => AclVerdict::Allow,
            AclAction::Deny => AclVerdict::Deny("default".into()),
        }
    }

    fn qos_class_index(&self, info: &PacketInfo) -> Option<usize> {
        if !self.file.qos.enabled {
            return None;
        }
        self.qos_order.iter().copied().find(|idx| {
            self.file.qos.classes[*idx].matches(
                info.src,
                info.dst,
                info.protocol,
                info.src_port,
                info.dst_port,
            )
        })
    }

    pub fn qos_priority(&self, info: &PacketInfo) -> i32 {
        self.qos_class_index(info)
            .map(|idx| self.file.qos.classes[idx].priority)
            .unwrap_or(0)
    }

    pub fn apply_qos(&self, packet: &mut [u8], info: &PacketInfo) -> QosVerdict {
        let Some(idx) = self.qos_class_index(info) else {
            return QosVerdict::Unmarked;
        };
        let class = &self.file.qos.classes[idx];
        if let Some(rate) = class.rate_pps {
            let burst = class.burst.unwrap_or(rate).max(1) as f64;
            let mut bucket = self.buckets[idx].lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let elapsed = now.duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * rate as f64).min(burst);
            bucket.last = now;
            if bucket.tokens < 1.0 {
                return QosVerdict::RateLimited;
            }
            bucket.tokens -= 1.0;
        }
        if let Some(rate) = class.rate_bps {
            let bytes = packet.len() as f64;
            let burst = class.burst_bytes.unwrap_or(rate).max(1) as f64;
            let mut bucket = self.byte_buckets[idx]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let elapsed = now.duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * rate as f64).min(burst);
            bucket.last = now;
            if bucket.tokens < bytes {
                return QosVerdict::RateLimited;
            }
            bucket.tokens -= bytes;
        }
        if crate::wire::set_dscp(packet, class.dscp) {
            QosVerdict::Marked(class.dscp)
        } else {
            QosVerdict::Unmarked
        }
    }
}

/// Route attributes can carry zone metadata for AZ-aware route selection.
pub fn zone_attrs(zone: Option<&str>) -> RouteAttributes {
    RouteAttributes {
        zone: zone.map(ToString::to_string),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn https_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 7, 0, 1]);
        p[16..20].copy_from_slice(&[10, 7, 0, 2]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p
    }

    #[test]
    fn acl_rule_hits_are_counted() {
        use stellaris_types::{AclConfig, AclRule};
        let acl = AclConfig {
            default_action: AclAction::Allow,
            rules: vec![AclRule {
                name: "deny-443".into(),
                action: AclAction::Deny,
                direction: AclDirection::Both,
                priority: 10,
                src: None,
                dst: None,
                protocol: Some(6),
                src_port: None,
                dst_port: Some(443),
                peer: None,
                zone: None,
            }],
        };
        let policy = Policy::from_config(acl, QosConfig::default());
        let info = PacketInfo::parse(&https_packet()).unwrap();
        assert!(matches!(
            policy.check(AclDirection::Inbound, &info, None, None),
            AclVerdict::Deny(_)
        ));
        assert_eq!(policy.acl_hits()[0].1, 1);
    }

    #[test]
    fn qos_byte_shaper_limits_bytes() {
        let len = https_packet().len();
        let cfg: QosConfig = toml::from_str(&format!(
            r#"
enabled = true
[[classes]]
name = "https"
dscp = 46
rate_bps = 1
burst_bytes = {}
dst_port = 443
"#,
            len * 2
        ))
        .unwrap();
        let policy = Policy::from_config(AclConfig::default(), cfg);
        let info = PacketInfo::parse(&https_packet()).unwrap();
        for _ in 0..2 {
            let mut packet = https_packet();
            assert_eq!(policy.apply_qos(&mut packet, &info), QosVerdict::Marked(46));
        }
        let mut packet = https_packet();
        assert_eq!(
            policy.apply_qos(&mut packet, &info),
            QosVerdict::RateLimited
        );
    }

    #[test]
    fn qos_token_bucket_limits_burst() {
        let cfg: QosConfig = toml::from_str(
            r#"
enabled = true
[[classes]]
name = "https"
dscp = 46
rate_pps = 1
burst = 1
dst_port = 443
"#,
        )
        .unwrap();
        let policy = Policy::from_config(AclConfig::default(), cfg);
        let info = PacketInfo::parse(&https_packet()).unwrap();
        let mut p1 = https_packet();
        assert_eq!(policy.apply_qos(&mut p1, &info), QosVerdict::Marked(46));
        let mut p2 = https_packet();
        assert_eq!(policy.apply_qos(&mut p2, &info), QosVerdict::RateLimited);
    }
}
