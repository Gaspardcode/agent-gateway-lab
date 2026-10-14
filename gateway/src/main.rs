use std::sync::Arc;
use std::time::Duration;

use agent_gateway::{policy::Policy, router, serve_tls, tls, AppState};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let policy_path = env("GATEWAY_POLICY", "/etc/agent-gateway/policy.yaml");
    let listen = env("GATEWAY_LISTEN", "127.0.0.1:8443");

    let policy = Policy::load(&policy_path)?;
    let tls_cfg = tls::server_config(
        &env("GATEWAY_CERT", "/etc/agent-gateway/tls/server.crt"),
        &env("GATEWAY_KEY", "/etc/agent-gateway/tls/server.key"),
        &env("GATEWAY_CLIENT_CA", "/etc/agent-gateway/tls/ca.crt"),
    )?;
    let timeout: u64 = env("GATEWAY_UPSTREAM_TIMEOUT_S", "300").parse()?;
    let http = reqwest::Client::builder().timeout(Duration::from_secs(timeout)).build()?;

    println!(
        "{}",
        json!({"event": "startup", "listen": listen, "mode": policy.mode,
               "upstream": policy.upstream, "clients": policy.clients.keys().collect::<Vec<_>>()})
    );
    let state = Arc::new(AppState { policy, http, limiter: Default::default() });
    let listener = TcpListener::bind(&listen).await?;
    serve_tls(listener, TlsAcceptor::from(Arc::new(tls_cfg)), router(state)).await
}
