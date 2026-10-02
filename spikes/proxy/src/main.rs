//! THROWAWAY: `cargo run` in this directory runs the spike and prints the report.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let report = proxy_spike::run().await?;
    println!("{report:#?}\nSPIKE OK: intercept (a), tunnel (b), plain http (c) all proven");
    Ok(())
}
