use std::net::SocketAddr;
use std::net::IpAddr;

use anyhow::anyhow;
use socks::Socks5Stream;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio::time::timeout;
use anyhow::Result;

use crate::ProxyConfig;


pub async fn connect(socket: SocketAddr, proxy_config: ProxyConfig,timeout_setting: u32) -> Result<TcpStream> {
    // 超时时间1秒
    let timeout_duration = Duration::from_secs(timeout_setting as u64);

    let stream = if proxy_config.socks5.enabled {
        // 代理连接
        match timeout(timeout_duration, async {
            let proxy_addr = format!("{}:{}", proxy_config.socks5.host, proxy_config.socks5.port);
            
            let stream = match (proxy_config.socks5.username, proxy_config.socks5.password) {
                (Some(username), Some(password)) => {
                    Socks5Stream::connect_with_password(
                        &proxy_addr,
                        socket,
                        &username,
                        &password
                    )
                },
                _ => Socks5Stream::connect(&proxy_addr, socket)
            }.map_err(|e| anyhow!("Proxy connection failed: {}", e))?;

            TcpStream::try_from(stream.into_inner())
                .map_err(|e| anyhow!("Failed to convert to TcpStream: {}", e))
        }).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(anyhow!("Proxy connection timed out"))
        }
    } else {
        // 直接连接
        match timeout(timeout_duration, TcpStream::connect(socket)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(anyhow!("Direct connection failed: {}", e)),
            Err(_) => Err(anyhow!("Connection timed out"))
        }
    }?;
    
    // 设置TCP选项 禁用 Nagle 算法
    stream.set_nodelay(true)?;
    
    Ok(stream)
}

