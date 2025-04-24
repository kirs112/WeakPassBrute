use std::net::SocketAddr;

use futures::stream;
use tokio::time::sleep;
use rdp::core::client::Connector;
use crate::{scan::BruteResult, utils::{parser::parse_user_pass_form_file, tcp_connect::connect}, ProxyConfig};
// use crate::{utils::tcp_connect::connect, ProxyConfig};
use tokio::time::Duration;
use futures::StreamExt;
use anyhow::{Result};
use fastrand;
use anyhow::anyhow;

#[derive(Debug, Clone)]
enum Credential {
    Hash(Vec<u8>),
    Password(String)
}

impl std::fmt::Display for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credential::Hash(hash) => {
                write!(f, "[hash: {:02x?}]", hash.iter().map(|x| format!("{:02x}", x)).collect::<String>())
            },
            Credential::Password(password) => {
                write!(f, "[pass: '{}']", password)
            }
        }
    }
}

pub struct RdpBrute {
    host: String,
    port: u16,
    timeout: u32,
    domain: String,
}

impl RdpBrute {
    pub fn new(host: String, port: u16, timeout: u32) -> Self {
        Self {
            host,
            port,
            timeout,
            domain: "WORKGROUP".to_string(),
        }
    }

    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = domain;
        self
    }

    pub async fn check_weak_pass(
        host: String,
        port: u16,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        _retries: u32,
        timeout: u32,
        _single_account: bool,
    ) -> Result<Vec<BruteResult>, anyhow::Error> {


        let mut rdp_brute_result = Vec::new();
        let mut rdp_brute = RdpBrute::new(host.to_string(), port, timeout);
        if username_suffix.is_empty() {
            rdp_brute.domain = "WORKGROUP".to_string();
        } else {
            rdp_brute.domain = username_suffix.to_string();
        }

        let usernames = parse_user_pass_form_file(&username);

        for username in usernames {
            let passwords = parse_user_pass_form_file(&password);

            // 减少并发数到3个，并在每次尝试后添加延时
            let password_stream = stream::iter(passwords);
            let mut concurrent_tasks = password_stream
                .map(|password| {
                    let username = username.clone();
                    let credential = Credential::Password(password.clone());
                    let rdp = &rdp_brute;
                    let proxy = proxy_config.clone();
                    async move {
                        // 添加随机延时 1-2 秒
                        sleep(Duration::from_millis(1000 + fastrand::u64(0..1000))).await;
                        match rdp.try_login(&username, &credential,proxy).await {
                            Ok(true) => (password.clone(), Ok(true)),
                            Ok(false) => (password.clone(), Ok(false)),
                            Err(e) => (password.clone(), Err(e)),
                        }
                    }
                })
                .buffer_unordered(3); // 将并发数从10降到3

            // 处理并发任务的结果
            while let Some((password, result)) = concurrent_tasks.next().await {
                match result {
                    Ok(true) => {
                        println!("RDP login success - {}:{} {}/{}", host, port, username, password);
                        rdp_brute_result.push(BruteResult::new(1,host.to_string(),"RDP".to_string(), port.into(), username.clone(),
                        password.clone(), "RDP".to_string(), "3".to_string()));
                        return Ok(rdp_brute_result);
                    }
                    _ => {
                         println!("RDP login failed - {}:{} {}/{}", host, port, username, password);
                    }
                }
            }
        }

        Ok(rdp_brute_result)
    }

    async fn try_login(&self, username: &str, credential: &Credential,proxy:ProxyConfig) -> Result<bool, anyhow::Error> {
        let addr = format!("{}:{}", self.host, self.port);
        let socket_addr: SocketAddr = addr.parse().unwrap();

        let tcp = connect(socket_addr,proxy,self.timeout as u32).await?;

        let tcp = tcp.into_std().unwrap();
        tcp.set_nonblocking(false).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(self.timeout as u64))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(self.timeout as u64))).unwrap();

        let mut connector = Connector::new().screen(800, 600);
        
        match credential {
            Credential::Password(password) => {
                connector = connector.credentials(
                    self.domain.clone(),
                    username.to_string(),
                    password.clone(),
                );
            },
            Credential::Hash(hash) => {
                connector = connector.credentials(
                    self.domain.clone(),
                    username.to_string(),
                    String::new(),
                );
                connector = connector.set_password_hash(hash.clone());
            }
        };

        match connector.connect(tcp) {
            Ok(mut client) => {
                if let Err(e) = client.shutdown() {
                    println!("[-] Warning: Failed to shutdown RDP client: {:?}", e);
                }
                Ok(true)
            },
            Err(e) => {
                if format!("{:?}", e).contains("authentication") {
                    println!("[-] RDP login failed - wrong credentials for {}/{}", username, credential);
                    Ok(false)
                } else {
                    println!("[-] RDP login error - {}:{} {}/{} - {:?}",
                        self.host, self.port, username, credential, e);
                    // Err(e);
                    Ok(false)
                }
            }
        }
    }
}

// #[cfg(test)]
// mod tests {
    
//     use crate::ProxyDetails;

//     use super::*;

//     #[tokio::test]
//     async fn test_rdp_brute() {
//         let proxy_config = ProxyConfig {
//             socks5: ProxyDetails {
//                 enabled: false,
//                 host: String::new(),
//                 port: String::new(),
//                 username: None,
//                 password: None,

//             }
//         };
//         // let rdp_brute = RdpBrute::new("192.168.1.1".to_string(), 3389, 10, "attack.local".to_string());
//         // let proxy = ProxyConfig::new("http://127.0.0.1:8080".to_string());
//         let result = RdpBrute::check_weak_pass("192.168.124.131".to_string(), 3389, "administrator".to_string(), "1qaz@WSX".to_string(),
//          proxy_config,10).await.unwrap();
//         println!("{:?}", result);
//     }

// }
