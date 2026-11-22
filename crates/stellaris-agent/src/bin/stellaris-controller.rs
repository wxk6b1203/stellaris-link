use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use stellaris_agent::controller;
use stellaris_types::Config;

#[derive(Debug, Parser)]
#[command(name = "stellaris-controller", version, about = "Stellaris controller")]
struct Args {
    #[arg(short, long, default_value = "controller.toml")]
    config: PathBuf,
    /// Print the controller iroh endpoint id and exit.
    #[arg(long)]
    print_id: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "stellaris_agent=info".into()),
        )
        .init();
    let args = Args::parse();
    let config = Config::load(&args.config)
        .with_context(|| format!("load config {}", args.config.display()))?;
    if args.print_id {
        let state_dir = PathBuf::from(&config.node.state_dir);
        std::fs::create_dir_all(&state_dir)?;
        let identity = stellaris_agent::identity::load_or_create(&state_dir)?;
        println!("{}", identity.node_id);
        return Ok(());
    }
    controller::run(config).await
}
