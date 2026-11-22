use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use stellaris_agent::{AgentState, run};
use stellaris_types::Config;

#[derive(Debug, Parser)]
#[command(name = "stellaris-agent", version, about = "Stellaris Linking agent")]
struct Args {
    /// Path to the agent TOML config.
    #[arg(short, long, default_value = "stellaris.toml")]
    config: PathBuf,
    /// Print this node's endpoint id (for peer configs) and exit.
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
    let config = Config::load(&args.config)
        .with_context(|| format!("load config {}", args.config.display()))?;
    let state = AgentState::build(config)?;
    if args.print_id {
        println!("{}", state.node_id);
        return Ok(());
    }
    run(state).await
}
