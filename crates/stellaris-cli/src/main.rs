use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use reqwest::{Client, Method, Response};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(name = "stellaris", version, about = "Stellaris Linking CLI")]
struct Cli {
    /// Agent API base URL.
    #[arg(long, env = "STELLARIS_API", default_value = "http://127.0.0.1:7777")]
    api: String,
    /// API token (if configured).
    #[arg(long, env = "STELLARIS_TOKEN")]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show agent status.
    Status,
    /// Peer commands.
    Peer {
        #[command(subcommand)]
        cmd: PeerCmd,
    },
    /// Route commands.
    Route {
        #[command(subcommand)]
        cmd: RouteCmd,
    },
}

#[derive(Debug, Subcommand)]
enum PeerCmd {
    /// List configured peers.
    List,
}

#[derive(Debug, Subcommand)]
enum RouteCmd {
    /// List intent/rib/fib routes.
    List {
        #[arg(long, default_value = "rib")]
        view: String,
    },
    /// Longest-prefix lookup.
    Lookup { dst: String },
    /// Explain route selection.
    Explain { dst: String },
    /// Add or update a static route.
    Add {
        prefix: String,
        #[arg(long)]
        via: String,
        #[arg(long)]
        metric: Option<u32>,
        #[arg(long)]
        admin_distance: Option<u8>,
        #[arg(long)]
        pin: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "cli")]
        reason: String,
    },
    /// Delete an intent by route id.
    Delete { id: String },
    /// Pin a prefix to a next hop.
    Pin {
        prefix: String,
        #[arg(long)]
        via: String,
        #[arg(long)]
        ttl: Option<u64>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a pin.
    Unpin {
        prefix: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Drain all local intents via a node.
    Drain {
        node: String,
        #[arg(long, default_value = "0")]
        grace: u64,
        #[arg(long)]
        dry_run: bool,
    },
    /// Reset static routes for a prefix (or all).
    Reset {
        prefix: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
}

struct ApiClient {
    client: Client,
    base: String,
    token: Option<String>,
}

impl ApiClient {
    fn new(base: String, token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base: base.trim_end_matches('/').to_string(),
            token,
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.client.request(method, &url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await.with_context(|| format!("request {url}"))?;
        parse_response(resp).await
    }
}

async fn parse_response(resp: Response) -> anyhow::Result<Value> {
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("HTTP {status}: {text}");
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn print(value: &Value) {
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let api = ApiClient::new(cli.api, cli.token);

    match cli.cmd {
        Command::Status => {
            let v = api.request(Method::GET, "/v1/status", None).await?;
            print(&v);
        }
        Command::Peer { cmd } => match cmd {
            PeerCmd::List => {
                let v = api.request(Method::GET, "/v1/peers", None).await?;
                print(&v);
            }
        },
        Command::Route { cmd } => match cmd {
            RouteCmd::List { view } => {
                let v = api
                    .request(Method::GET, &format!("/v1/routes?view={view}"), None)
                    .await?;
                print(&v);
            }
            RouteCmd::Lookup { dst } => {
                let v = api
                    .request(Method::GET, &format!("/v1/routes/lookup?dst={dst}"), None)
                    .await?;
                print(&v);
            }
            RouteCmd::Explain { dst } => {
                let v = api
                    .request(Method::GET, &format!("/v1/routes/explain?dst={dst}"), None)
                    .await?;
                print(&v);
            }
            RouteCmd::Add {
                prefix,
                via,
                metric,
                admin_distance,
                pin,
                dry_run,
                reason,
            } => {
                let body = json!({
                    "change": {
                        "kind": "upsert_static",
                        "prefix": prefix,
                        "via": via,
                        "admin_distance": admin_distance,
                        "local_pref": null,
                        "metric": metric,
                        "weight": null,
                        "pin": pin,
                        "expires_at": null,
                        "attrs": {
                            "rtt_ms": null,
                            "loss_ppm": null,
                            "bandwidth_kbps": null,
                            "energy_cost": null,
                            "region": null,
                            "tags": []
                        }
                    },
                    "scope": "local",
                    "dry_run": dry_run,
                    "reason": reason
                });
                let v = api.request(Method::POST, "/v1/routes", Some(body)).await?;
                print(&v);
            }
            RouteCmd::Delete { id } => {
                let v = api
                    .request(Method::DELETE, &format!("/v1/routes/{id}"), None)
                    .await?;
                print(&v);
            }
            RouteCmd::Pin {
                prefix,
                via,
                ttl,
                dry_run,
            } => {
                let body = json!({
                    "prefix": prefix,
                    "next_hop": via,
                    "ttl_secs": ttl,
                    "dry_run": dry_run
                });
                let v = api
                    .request(Method::POST, "/v1/routes/pin", Some(body))
                    .await?;
                print(&v);
            }
            RouteCmd::Unpin { prefix, dry_run } => {
                let body = json!({"prefix": prefix, "dry_run": dry_run});
                let v = api
                    .request(Method::POST, "/v1/routes/unpin", Some(body))
                    .await?;
                print(&v);
            }
            RouteCmd::Drain {
                node,
                grace,
                dry_run,
            } => {
                let body = json!({"node": node, "grace_secs": grace, "dry_run": dry_run});
                let v = api
                    .request(Method::POST, "/v1/routes/drain", Some(body))
                    .await?;
                print(&v);
            }
            RouteCmd::Reset { prefix, dry_run } => {
                let body = json!({"prefix": prefix, "dry_run": dry_run});
                let v = api
                    .request(Method::POST, "/v1/routes/reset", Some(body))
                    .await?;
                print(&v);
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn parses_status_and_peer_commands() {
        assert!(matches!(
            parse(&["stellaris", "status"]).cmd,
            Command::Status
        ));
        assert!(matches!(
            parse(&["stellaris", "peer", "list"]).cmd,
            Command::Peer { cmd: PeerCmd::List }
        ));
    }

    #[test]
    fn parses_route_mutations() {
        let cli = parse(&[
            "stellaris",
            "route",
            "add",
            "10.9.0.0/16",
            "--via",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "--metric",
            "7",
            "--pin",
            "--dry-run",
            "--reason",
            "test",
        ]);
        match cli.cmd {
            Command::Route {
                cmd:
                    RouteCmd::Add {
                        prefix,
                        via,
                        metric,
                        pin,
                        dry_run,
                        reason,
                        ..
                    },
            } => {
                assert_eq!(prefix, "10.9.0.0/16");
                assert!(via.starts_with("0202"));
                assert_eq!(metric, Some(7));
                assert!(pin && dry_run);
                assert_eq!(reason, "test");
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(matches!(
            parse(&["stellaris", "route", "delete", "abc"]).cmd,
            Command::Route {
                cmd: RouteCmd::Delete { .. }
            }
        ));
        assert!(matches!(
            parse(&["stellaris", "route", "lookup", "10.0.0.1"]).cmd,
            Command::Route {
                cmd: RouteCmd::Lookup { .. }
            }
        ));
        let cli = parse(&[
            "stellaris",
            "route",
            "pin",
            "10.9.0.0/16",
            "--via",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "--ttl",
            "30",
        ]);
        assert!(matches!(
            cli.cmd,
            Command::Route {
                cmd: RouteCmd::Pin { ttl: Some(30), .. }
            }
        ));
    }

    #[test]
    fn rejects_missing_required_arguments() {
        assert!(Cli::try_parse_from(["stellaris", "route", "add", "10.9.0.0/16"]).is_err());
        assert!(Cli::try_parse_from(["stellaris", "route"]).is_err());
        assert!(Cli::try_parse_from(["stellaris", "unknown"]).is_err());
    }
}
