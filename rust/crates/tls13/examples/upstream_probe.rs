//! No-credential public-network probe using the actual two-party TLS 1.3 engine.
//! Sends a GET only; never reads API credentials or calls model inference.
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tlsn_core::webpki::RootCertStore;
use tokenhive_tls13::{Policy, hub_handshake, provider_handshake};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

struct CaptureHello {
    stream: tokio::net::TcpStream,
    hello: Arc<Mutex<Vec<u8>>>,
    complete: bool,
}
impl AsyncRead for CaptureHello {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for CaptureHello {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_write(cx, bytes) {
            Poll::Ready(Ok(n)) => {
                if !this.complete {
                    let mut hello = this
                        .hello
                        .lock()
                        .map_err(|_| std::io::Error::other("capture lock"))?;
                    let available = 4096usize.saturating_sub(hello.len());
                    hello.extend_from_slice(&bytes[..n.min(available)]);
                    if hello.len() >= 5 {
                        let len = 5 + u16::from_be_bytes([hello[3], hello[4]]) as usize;
                        if hello[0] != 22 || len > 4096 {
                            return Poll::Ready(Err(std::io::Error::other(
                                "unexpected ClientHello record",
                            )));
                        }
                        if hello.len() >= len {
                            hello.truncate(len);
                            this.complete = true;
                        }
                    }
                }
                Poll::Ready(Ok(n))
            }
            result => result,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: upstream_probe DNS_HOST /PUBLIC_GET_PATH CLIENTHELLO_OUTPUT.bin".into(),
        );
    }
    let (host, path) = (&args[0], &args[1]);
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || !path.starts_with('/')
        || path.len() > 512
        || !path.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err("invalid DNS host or origin-form GET path".into());
    }
    let hello = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let mut stage = "connect";
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        let stream = tokio::net::TcpStream::connect((host.as_str(), 443)).await?;
        stream.set_nodelay(true)?;
        let upstream = CaptureHello {
            stream,
            hello: hello.clone(),
            complete: false,
        };
        let (a, b) = tokio::io::duplex(1 << 20);
        let (output, mut response) = tokio::io::duplex(1 << 20);
        let policy = Policy {
            server_name: host.clone(),
            max_request: 4096,
            max_response: 1 << 20,
        };
        stage = "authenticated_mpc_handshake";
        let (mut hub, mut provider) = tokio::try_join!(
            hub_handshake(a, output, RootCertStore::mozilla(), policy.clone()),
            provider_handshake(b, upstream, policy)
        )?;
        let warm_ms = started.elapsed().as_secs_f64() * 1000.;
        // Public test bytes fill a generic header, not Authorization. No real
        // credential is used, loaded, logged or sent by this diagnostic.
        let credential = b"public-probe";
        let mut request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nX-TokenHive-Probe: ").into_bytes();
        let start = request.len();
        request.resize(start + credential.len(), 0);
        let end = request.len();
        request.extend_from_slice(b"\r\nConnection: close\r\nAccept: */*\r\n\r\n");
        stage = "credential_header_keyupdate_and_suffix";
        tokio::try_join!(
            hub.request(&request, start..end),
            provider.request(&request, start..end, credential)
        )?;
        stage = "authenticated_http_response";
        let reader = tokio::spawn(async move {
            let mut bytes = Vec::new();
            let result = response.read_to_end(&mut bytes).await;
            (bytes, result)
        });
        let authenticated_close = hub.response().await.is_ok();
        drop(hub);
        drop(provider);
        let (bytes, read_result) = reader.await?;
        read_result?;
        let line = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
        let status = std::str::from_utf8(line)
            .ok()
            .filter(|line| line.starts_with("HTTP/1.1 "))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse::<u16>().ok());
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((warm_ms, status, authenticated_close))
    })
    .await;
    let hello = hello.lock().map_err(|_| "capture lock")?;
    if !hello.is_empty() {
        std::fs::write(&args[2], hello.as_slice())?;
    }
    let (warm_ms, status, authenticated_close, error) = match result {
        Ok(Ok((warm, status, close))) => (Some(warm), status, close, None),
        Ok(Err(_)) => (None, None, false, Some("operation_failed")),
        Err(_) => (None, None, false, Some("timeout")),
    };
    println!(
        "{}",
        serde_json::json!({
            "host": host, "path": path, "stage": stage, "error": error,
            "warm_ms": warm_ms, "total_ms": started.elapsed().as_secs_f64()*1000.,
            "http_status": status, "authenticated_close": authenticated_close,
            "client_hello_captured": !hello.is_empty(), "real_two_party_mpc": true,
            "authorization_sent": false, "paid_inference_called": false,
            "full_request_consumption_confirmed": false,
            "early_response_detection": "not_available_in_pull_relay",
            "scope": "This runner's exit network only; not production Provider admission. A 401/403 may precede full request consumption."
        })
    );
    if status.is_none() || !authenticated_close {
        std::process::exit(1);
    }
    Ok(())
}
