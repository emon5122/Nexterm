use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response;
use tokio_tungstenite::{client_async_tls, MaybeTlsStream, WebSocketStream};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Drop-in replacement for `tokio_tungstenite::connect_async`.
///
/// `connect_async` tries the resolved addresses in order with no per-address timeout, so a
/// broken IPv6 route (e.g. Cloudflare WARP advertising IPv6 that silently drops traffic)
/// makes it hang until the kernel's TCP timeout. We try IPv4 first and give each address a
/// short timeout before moving on.
pub async fn connect(url: &str) -> Result<(WsStream, Response)> {
    let request = url.into_client_request()?;
    let uri = request.uri();
    let host = uri.host().context("WebSocket URL has no host")?.trim_matches(['[', ']']).to_string();
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") { 443 } else { 80 });

    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await
        .with_context(|| format!("Failed to resolve {host}"))?
        .collect();
    addrs.sort_by_key(|a| a.is_ipv6());

    let mut last_err = None;
    for addr in addrs {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(client_async_tls(request, stream).await?),
            Ok(Err(e)) => last_err = Some(anyhow::anyhow!("{addr}: {e}")),
            Err(_) => last_err = Some(anyhow::anyhow!("{addr}: connect timed out")),
        }
    }
    match last_err {
        Some(e) => Err(e.context(format!("Could not connect to {host}:{port}"))),
        None => bail!("{host} resolved to no addresses"),
    }
}
