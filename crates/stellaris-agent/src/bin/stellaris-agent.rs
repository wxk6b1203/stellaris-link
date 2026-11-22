use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use stellaris_agent::{AgentState, run};
use stellaris_types::Config;

#[derive(Debug, Parser)]
#[command(name = "stellaris-agent", version, about = "Stellaris Linking agent")]
struct Args {
    /// Path to an agent TOML config. Repeat for multiple networks in one process.
    #[arg(short, long, action = clap::ArgAction::Append)]
    config: Vec<PathBuf>,
    /// Print this node's endpoint id (one config only) and exit.
    #[arg(long)]
    print_id: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "stellaris_agent=info,stellaris_routing=info".into()),
        )
        .init();

    let args = Args::parse();
    let paths = if args.config.is_empty() {
        vec![PathBuf::from("stellaris.toml")]
    } else {
        args.config
    };
    if args.print_id && paths.len() > 1 {
        bail!("--print-id supports exactly one --config");
    }
    let mut configs = Vec::with_capacity(paths.len());
    let mut state_dirs = HashSet::new();
    let mut networks = HashSet::new();
    for path in &paths {
        let config =
            Config::load(path).with_context(|| format!("load config {}", path.display()))?;
        if !state_dirs.insert(config.node.state_dir.clone()) {
            bail!(
                "duplicate node.state_dir {} across configs",
                config.node.state_dir
            );
        }
        let network = config.network.id.unwrap_or_else(|| {
            stellaris_types::NetworkId(uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_DNS,
                config.network.name.as_bytes(),
            ))
        });
        if !networks.insert(network) {
            bail!(
                "duplicate network {} across configs; use distinct network ids/names",
                network
            );
        }
        configs.push(config);
    }

    let mut states = Vec::with_capacity(configs.len());
    for config in configs {
        states.push(AgentState::build(config)?);
    }
    if args.print_id {
        println!("{}", states[0].node_id);
        return Ok(());
    }
    if states.len() == 1 {
        return run(states.pop().expect("one state")).await;
    }

    let mut set = tokio::task::JoinSet::new();
    for state in states {
        let node = state.node_id;
        let network = state.network;
        set.spawn(async move { (node, network, run(state).await) });
    }
    let mut failure: Option<anyhow::Error> = None;
    while let Some(result) = set.join_next().await {
        match result {
            Ok((node, network, Ok(()))) => {
                tracing::info!(%node, %network, "network runtime stopped");
            }
            Ok((node, network, Err(e))) => {
                failure = Some(e.context(format!("network {network} node {node} runtime failed")));
                break;
            }
            Err(e) => {
                failure = Some(anyhow::anyhow!("network runtime task failed: {e}"));
                break;
            }
        }
    }
    set.shutdown().await;
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
