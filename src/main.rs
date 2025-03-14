use anyhow::Result;
use merka_vault::cli;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Dispatch the CLI commands.
    cli::run_cli().await?;
    Ok(())
}
