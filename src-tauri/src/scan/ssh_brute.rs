
use std::net::ToSocketAddrs;
use anyhow::Result;
use anyhow::anyhow;

use futures::stream;
use ssh2::Session;
use tokio::time::Duration;
use crate::utils::parser::parse_user_pass_form_file;
use crate::{utils::tcp_connect::connect, ProxyConfig};
use futures::StreamExt;

use super::BruteResult;

#[derive(Debug,Clone)]
pub struct SshBrute {
    host: String,
    port: u16,
    username: String,
    password: String,
    timeout: u32,
}

impl SshBrute {
    pub fn new(host: String, port: u16, username: String, password: String,timeout: u32) -> Self {
        Self {
            host,
            port,
            username,
            password,
            timeout,
        }
    }

    pub async fn check(&self,proxy_config:ProxyConfig) -> Result<Vec<BruteResult>, anyhow::Error> {
        let target = format!("{}:{}", self.host, self.port);
        let mut brute_result = Vec::new();
        
        match tokio::time::timeout(Duration::from_secs(self.timeout as u64),
         connect(target.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Invalid address"))?,proxy_config,self.timeout as u32)).await {
            Ok(Ok(tcp)) => {
                tcp.set_nodelay(true).unwrap();

                let mut session = Session::new().unwrap();
                session.set_tcp_stream(tcp);
                
                match tokio::time::timeout(Duration::from_secs(self.timeout as u64), async {
                    session.handshake().unwrap();
                    session.userauth_password(&self.username, &self.password)
                }).await {
                    Ok(Ok(_)) => {
                        println!("SSH authentication successful - {}:{} username: {} password: {}", self.host, self.port, self.username, self.password);
                       brute_result.push( BruteResult::new(1,self.host.clone(), "SSH".to_string(),self.port.into(), self.username.clone(), self.password.clone(), "ssh".to_string(),3.to_string()));
                        Ok(brute_result)
                    },
                    Ok(Err(_)) => Ok(brute_result),
                    Err(_) => Err(anyhow!("Handshake timeout")),
                }
            },
            Ok(Err(e)) => Err(anyhow!(format!("Failed to connect: {}", e))),
            Err(_) => Err(anyhow!("Connection timeout")),
        }
    }

    pub async fn check_weak_pass(
        host: String,
        port: u16,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        _username_suffix: String,
        _retries: u32,
        timeout: u32,
        _single_account: bool,
    ) -> anyhow::Result<Vec<BruteResult>, anyhow::Error> {

        let mut vuln_result = Vec::new();

        let usernames = parse_user_pass_form_file(&username);
        let passwords = parse_user_pass_form_file(&password);

        for username in usernames {

            // 将密码列表转换为并发流
            let password_stream = stream::iter(passwords.clone());
            let mut concurrent_tasks = password_stream
                .map(|password| {
                    let host = host.to_string();
                    let username = username.clone();
                    let proxy_config = proxy_config.clone();
                    async move {
                        let brute = SshBrute::new(
                            host,
                            port,
                            username,
                            password,
                            timeout,
                        );
                        brute.check(proxy_config).await
                    }
                })
                .buffer_unordered(10);

            // 处理并发任务的结果
            while let Some(result) = concurrent_tasks.next().await {
                if let Ok(result) = result {
                    // println!("SSH authentication successful - {}:{} username: {} password: {}", host, port, username, password);
                    vuln_result.extend(result);
                    
                }
            }
        }
        Ok(vuln_result)
    }


}


// #[cfg(test)]
//     mod tests {
//         use crate::ProxyDetails;

//         use super::*;
//         #[tokio::test]
//         async fn test_check_weak_pass() {
//             let host = "192.168.254.128".to_string();
//             let port = 22;
//             let username_file = "d:\\安全工具\\字典\\fuzzDicts-master\\fuzzDicts-master\\passwordDict\\ServiceWeakPass\\ssh弱口令\\ssh-user.txt".to_string();
//             let password_file = "d:\\安全工具\\字典\\fuzzDicts-master\\fuzzDicts-master\\passwordDict\\ServiceWeakPass\\ssh弱口令\\ssh-pass.txt".to_string();
//             let timeout = 5;
             
//             let proxy_details = ProxyDetails {
//                 enabled: false,
//                 host: String::from("127.0.0.1"),
//                 password: Option::None,
//                 port: String::from("7897"),
//                 username: Option::None,
//             };
        
//             // 使用 ProxyDetails 实例创建一个 ProxyConfig 实例
//             let proxy_config = ProxyConfig {
//                 socks5: proxy_details,
//             };

//             let result = SshBrute::check_weak_pass(host, port, username_file, password_file, proxy_config,timeout).await.unwrap();
//             println!("{:?}",result);
//         }
    
// }
