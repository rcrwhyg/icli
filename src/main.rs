use clap::Parser;
use rcli::{CommandExecutor, Opts};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts: Opts = Opts::parse();
    opts.cmd.execute().await?;

    Ok(())
}
