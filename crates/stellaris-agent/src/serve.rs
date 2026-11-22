//! HTTP/HTTPS serving shared by the agent API and controller.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;

pub async fn serve(
    addr: SocketAddr,
    app: Router,
    tls: Option<(String, String)>,
    label: &'static str,
) -> anyhow::Result<()> {
    let handle = Handle::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            handle.graceful_shutdown(Some(Duration::from_secs(5)));
        });
    }
    match tls {
        Some((cert, key)) => {
            let config = RustlsConfig::from_pem_file(&cert, &key)
                .await
                .with_context(|| format!("load {label} TLS cert={cert} key={key}"))?;
            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(app.into_make_service())
                .await
                .with_context(|| format!("{label} HTTPS server"))
        }
        None => axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .with_context(|| format!("{label} HTTP server")),
    }
}
