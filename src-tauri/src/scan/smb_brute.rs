use std::net::ToSocketAddrs;
use anyhow::{Result, anyhow};
use futures::stream::{self, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{
    scan::BruteResult, utils::{parser::parse_user_pass_form_file, smb_connect::{Conn, SmbOptions}, tcp_connect::connect}, ProxyConfig
};

#[derive(Clone)]
pub struct SmbBrute {
    host: String,
    port: u16,
    timeout: u32,
    domain: String,
}

impl SmbBrute {
    pub fn new(host: String, port: u16, timeout: u32) -> Self {
        // let mut domain = domain;
        // if domain.is_empty() {
        //     domain = "WORKGROUP".to_string();
        // }
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

    async fn try_login(&self, username: &str, password: &str, proxy_config: ProxyConfig) -> Result<bool> {
        const MAX_RETRIES: u32 = 3;
        let mut retry_count = 0;


        while retry_count < MAX_RETRIES {

            let op = SmbOptions{
                Host:        self.host.as_str(),
                Port:        "445",
                User:        username,
                Domain:      &self.domain,
                Workstation: "",
                Password:    password,
        };

            let mut result = Conn(op,proxy_config.clone(),self.timeout as u32).await?;
            result.IsAuthenticated();
            if result.StatusCode == 0 {
                return Ok(true);
            }else {
                retry_count += 1;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        }
        
        Err(anyhow!("Max retries exceeded"))
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

    ) -> Result<Vec<BruteResult>> {
        let mut brute_results = Vec::new();
        let usernames = parse_user_pass_form_file(&username);

        let mut brute = SmbBrute::new(
            host.clone(),
            port,
            timeout,
        );
        if username_suffix.is_empty() {
            brute.domain = "WORKGROUP".to_string();
        } else {
            brute.domain = username_suffix.to_string();
        }

        for username in usernames {
            let passwords = parse_user_pass_form_file(&password);
            
            let password_stream = stream::iter(passwords);
            let mut concurrent_tasks = password_stream
                .map(|password| {
                    let username = username.clone();
                    let proxy_config = proxy_config.clone();
                    // let domain = domain.clone();
                    // let host = host.clone();
                    let run_check = brute.clone();
                    async move {
                        let result = run_check.try_login(&username, &password, proxy_config).await;
                        (username, password, result)
                    }
                })
                .buffer_unordered(10);

            while let Some((username, password, result)) = concurrent_tasks.next().await {
                match result {
                    Ok(true) => {
                        println!("[+] SMB login success - {}:{} {}/{}", 
                           host, port, username, password);
                        brute_results.push(BruteResult::new(
                            brute_results.len() as i32 + 1,
                            host.clone(),
                            "SMB".to_string(),
                            port as i32,
                            username,
                            password,
                            "Windows SMB".to_string(),
                            "3".to_string(),
                        ));
                    }
                    Ok(false) => {
                        println!("[-] SMB login failed - {}:{} {}/{}", 
                            host,port, username, password);
                    }
                    Err(e) => {
                        println!("[-] SMB login error - {}:{} {}/{} - {:?}", 
                            host, port, username, password, e);
                    }
                }
            }
        }

        Ok(brute_results)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::ProxyDetails;

//     #[tokio::test]
//     async fn test_smb_brute() {
//         let proxy_config = ProxyConfig {
//             socks5: ProxyDetails {
//                 enabled: false,
//                 host: String::new(),
//                 port: String::new(),
//                 username: None,
//                 password: None,
//             }
//         };

//         // let brute = SmbBrute::new(
//         //     "192.168.124.131".to_string(),
//         //     445,
//         //     15, // 增加超时时间到15秒
//         //     "attack.local".to_string(),
//         // );

//         let result = SmbBrute::check_weak_pass(
//             "192.168.124.131".to_string(),
//             445,
//             "administrator".to_string(),
//             "1qaz@WSX".to_string(),
//             proxy_config,
//             "attack.local".to_string(),
//             15, // 增加超时时间到15秒
//         ).await;

//         match result {
//             Ok(results) => println!("Brute force results: {:?}", results),
//             Err(e) => println!("Error during brute force: {:?}", e),
//         }
//     }
// }







