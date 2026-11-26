//! Controller administration over the control HTTP API.

use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use reqwest::{Method, Response};
use serde_json::{Value, json};

#[derive(Debug, Args)]
pub struct ControllerConn {
    /// Controller base URL.
    #[arg(
        long,
        env = "STELLARIS_CONTROLLER",
        default_value = "http://127.0.0.1:5801"
    )]
    pub url: String,
    /// Admin secret (`x-stellaris-secret`).
    #[arg(long, env = "STELLARIS_ADMIN_SECRET")]
    pub admin_secret: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum ControllerCmd {
    /// Controller status.
    Status,
    /// Membership admission queue.
    Admissions {
        #[command(subcommand)]
        cmd: AdmissionCmd,
    },
    /// Members and authorization.
    Members {
        #[command(subcommand)]
        cmd: MemberCmd,
    },
    /// Address pool and lease management.
    Ipam {
        #[command(subcommand)]
        cmd: IpamCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum AdmissionCmd {
    /// List pending enrollments.
    List,
    /// Approve a pending node.
    Approve {
        node: String,
        #[arg(long = "prefix")]
        prefixes: Vec<String>,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
    },
    /// Deny a pending node.
    Deny { node: String },
}

#[derive(Debug, Subcommand)]
pub enum MemberCmd {
    /// List members and current revisions.
    List,
    /// Revoke a member (releases its lease and fences its credential).
    Revoke { node: String },
    /// Replace a member's prefixes/capabilities.
    Grants {
        node: String,
        #[arg(long = "prefix")]
        prefixes: Vec<String>,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum IpamCmd {
    /// Pool commands.
    Pools {
        #[command(subcommand)]
        cmd: PoolCmd,
    },
    /// Lease commands.
    Leases {
        #[command(subcommand)]
        cmd: LeaseCmd,
    },
    /// Reservation commands.
    Reservations {
        #[command(subcommand)]
        cmd: ReservationCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum PoolCmd {
    List,
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        cidr: String,
        /// Optional inclusive range, e.g. 10.7.0.10-10.7.0.200.
        #[arg(long)]
        range: Option<String>,
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        lease_secs: u64,
        #[arg(long, default_value_t = 60)]
        quarantine_secs: u64,
        #[arg(long)]
        zone: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    Delete {
        id: String,
        /// Release the pool's leases and delete it.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum LeaseCmd {
    List,
    Renew {
        node: String,
    },
    Release {
        node: String,
    },
    Reassign {
        node: String,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReservationCmd {
    Add {
        node: String,
        #[arg(long)]
        ip: String,
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    Remove {
        node: String,
    },
}

struct Client {
    http: reqwest::Client,
    base: String,
    admin: Option<String>,
}

impl Client {
    fn new(conn: &ControllerConn) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            base: conn.url.trim_end_matches('/').to_string(),
            admin: conn.admin_secret.clone(),
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        let mut request = self.http.request(method, format!("{}{path}", self.base));
        if let Some(admin) = &self.admin {
            request = request.header("x-stellaris-secret", admin);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.context("controller request")?;
        parse(response).await
    }
}

async fn parse(response: Response) -> anyhow::Result<Value> {
    let status = response.status();
    let text = response.text().await.context("read controller response")?;
    if !status.is_success() {
        bail!(
            "controller returned {status}: {}",
            text.trim().chars().take(500).collect::<String>()
        );
    }
    if text.trim().is_empty() {
        return Ok(json!({ "ok": true }));
    }
    serde_json::from_str(&text)
        .with_context(|| format!("controller returned non-JSON: {}", text.trim()))
}

pub async fn run(conn: ControllerConn, cmd: ControllerCmd) -> anyhow::Result<()> {
    let client = Client::new(&conn);
    let value = match cmd {
        ControllerCmd::Status => client.request(Method::GET, "/v1/status", None).await?,
        ControllerCmd::Admissions { cmd } => match cmd {
            AdmissionCmd::List => client.request(Method::GET, "/v1/admissions", None).await?,
            AdmissionCmd::Approve {
                node,
                prefixes,
                capabilities,
            } => {
                client
                    .request(
                        Method::POST,
                        &format!("/v1/admissions/{node}/approve"),
                        Some(json!({
                            "prefixes": prefixes,
                            "capabilities": capabilities,
                        })),
                    )
                    .await?
            }
            AdmissionCmd::Deny { node } => {
                client
                    .request(
                        Method::POST,
                        &format!("/v1/admissions/{node}/deny"),
                        Some(json!({})),
                    )
                    .await?
            }
        },
        ControllerCmd::Members { cmd } => match cmd {
            MemberCmd::List => {
                let model = client.request(Method::GET, "/v1/model", None).await?;
                json!({
                    "members": model.get("members").cloned().unwrap_or(Value::Null),
                    "member_revisions": model.get("member_revisions").cloned().unwrap_or(Value::Null),
                })
            }
            MemberCmd::Revoke { node } => {
                client
                    .request(Method::POST, "/v1/revoke", Some(json!({ "node_id": node })))
                    .await?
            }
            MemberCmd::Grants {
                node,
                prefixes,
                capabilities,
            } => {
                client
                    .request(
                        Method::POST,
                        &format!("/v1/members/{node}/grants"),
                        Some(json!({
                            "prefixes": prefixes,
                            "capabilities": capabilities,
                        })),
                    )
                    .await?
            }
        },
        ControllerCmd::Ipam { cmd } => match cmd {
            IpamCmd::Pools { cmd } => match cmd {
                PoolCmd::List => client.request(Method::GET, "/v1/ipam/pools", None).await?,
                PoolCmd::Create {
                    id,
                    cidr,
                    range,
                    exclude,
                    lease_secs,
                    quarantine_secs,
                    zone,
                    description,
                } => {
                    let mut body = json!({
                        "id": id,
                        "cidr": cidr,
                        "exclude": exclude,
                        "lease_secs": lease_secs,
                        "quarantine_secs": quarantine_secs,
                    });
                    if let Some(range) = range {
                        let (start, end) = range
                            .split_once('-')
                            .ok_or_else(|| anyhow::anyhow!("--range must be START-END"))?;
                        body["range"] = json!([start.trim(), end.trim()]);
                    }
                    if let Some(zone) = zone {
                        body["zone"] = json!(zone);
                    }
                    if let Some(description) = description {
                        body["description"] = json!(description);
                    }
                    client
                        .request(Method::POST, "/v1/ipam/pools", Some(body))
                        .await?
                }
                PoolCmd::Delete { id, force } => {
                    client
                        .request(
                            Method::DELETE,
                            &format!("/v1/ipam/pools/{id}?force={force}"),
                            None,
                        )
                        .await?
                }
            },
            IpamCmd::Leases { cmd } => match cmd {
                LeaseCmd::List => client.request(Method::GET, "/v1/ipam/leases", None).await?,
                LeaseCmd::Renew { node } => {
                    client
                        .request(
                            Method::POST,
                            &format!("/v1/ipam/leases/{node}/renew"),
                            Some(json!({})),
                        )
                        .await?
                }
                LeaseCmd::Release { node } => {
                    client
                        .request(
                            Method::POST,
                            &format!("/v1/ipam/leases/{node}/release"),
                            Some(json!({})),
                        )
                        .await?
                }
                LeaseCmd::Reassign {
                    node,
                    ip,
                    pool,
                    zone,
                } => {
                    client
                        .request(
                            Method::POST,
                            &format!("/v1/ipam/leases/{node}/reassign"),
                            Some(json!({ "ip": ip, "pool": pool, "zone": zone })),
                        )
                        .await?
                }
            },
            IpamCmd::Reservations { cmd } => match cmd {
                ReservationCmd::Add {
                    node,
                    ip,
                    pool,
                    note,
                } => {
                    client
                        .request(
                            Method::POST,
                            "/v1/ipam/reservations",
                            Some(json!({
                                "node": node,
                                "ip": ip,
                                "pool": pool,
                                "note": note,
                            })),
                        )
                        .await?
                }
                ReservationCmd::Remove { node } => {
                    client
                        .request(
                            Method::DELETE,
                            &format!("/v1/ipam/reservations/{node}"),
                            None,
                        )
                        .await?
                }
            },
        },
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
