use std::{net::ToSocketAddrs, time::Duration};
use anyhow::{Result, anyhow};
use tiberius::{Client, Config, AuthMethod, error::Error as SqlError};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};
use futures::stream::{self, StreamExt};

use crate::{utils::{parser::parse_user_pass_form_file, tcp_connect::connect}, ProxyConfig, ProxyDetails};

#[derive(Clone)]
pub struct MssqlBrute {
    host: String,
    port: u16,
    timeout: u32,
}

impl MssqlBrute {
    pub fn new(host: String, port: u16, timeout: u32) -> Self {
        Self {
            host,
            port,
            timeout,
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
    ) -> Result<bool> {

        let scanner = MssqlBrute::new(host.to_string(), port, timeout);

        // 获取用户名列表
        let usernames = parse_user_pass_form_file(&username);

        // 尝试每个用户名和密码组合
        for username in usernames {
            // 获取密码列表
            let passwords = parse_user_pass_form_file(&password);
            // 将密码列表转换为并发流
            let password_stream = stream::iter(passwords);
            let mut concurrent_tasks = password_stream
                .map(|password| {
                    let scanner = scanner.clone();
                    let username = username.clone();
                    let proxy_config = proxy_config.clone();
                    async move {
                        let result = scanner.try_login(&username, &password,proxy_config).await;
                        (password, result)
                    }
                })
                .buffer_unordered(10);

            // 处理并发任务的结果
            while let Some((password, result)) = concurrent_tasks.next().await {
                match result {
                    Ok(true) => {
                        // output::success(&format!(
                        //     "[+] MSSQL login success - {}:{} {}/{}",
                        //     host, port, username, password
                        // ));
                        // add_vulnerability(
                        //     host,
                        //     port,
                        //     "MSSQL Brute-Force".to_string(),
                        //     "MSSQL Weak Password".to_string(),
                        //     Some(username.clone()),
                        //     Some(password.clone()),
                        // );
                        println!("MSSQL login success - {}:{} {}/{}", host, port, username, password);
                        return Ok(true);
                    }
                    Ok(false) => {
                        println!("[-] MSSQL login error - {}:{} {}/{} - Login failed",
                            host, port, username, password);
                        continue;
                    },
                    Err(e) => {
                        if !e.to_string().contains("Login failed") {
                            println!("[-] MSSQL login error - {}:{} {}/{} - {:?}",
                                host, port, username, password, e);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    async fn try_login(&self, username: &str, password: &str,proxy_config:ProxyConfig) -> Result<bool> {
        let mut config = Config::new();
        config.host(&self.host);
        config.port(self.port);
        config.authentication(AuthMethod::sql_server(username, password));
        config.trust_cert();

        let addr = format!("{}:{}", self.host, self.port);

        let tcp = connect(addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Invalid address"))?,proxy_config,self.timeout as u32).await?;
        tcp.set_nodelay(true)?;

        match tokio::time::timeout(Duration::from_secs(self.timeout as u64), Client::connect(config, tcp.compat_write())).await {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(e)) => {
                println!("[-] MSSQL login error - {}:{} {}/{} - {:?}", self.host, self.port, username, password, e);
                match e {
                    SqlError::Protocol(ref e) if e.to_string().contains("Login failed") => Ok(false),
                    _ => Err(anyhow!(e))
                }
            }
            Err(_) => Err(anyhow!("Connection timeout"))
        }
    }

    // pub async fn get_version(&self, username: &str, password: &str) -> Result<String> {
    //     let mut config = Config::new();
    //     config.host(&self.host);
    //     config.port(self.port);
    //     config.authentication(AuthMethod::sql_server(username, password));
    //     config.trust_cert();

    //     let tcp = TcpStream::connect(format!("{}:{}", self.host, self.port)).await?;
    //     tcp.set_nodelay(true)?;

    //     let mut client = Client::connect(config, tcp.compat_write()).await?;
        
    //     let version = self.get_version_from_client(&mut client).await?;

    //     Ok(version)
    // }

    // async fn get_version_from_client(&self, client: &mut Client<Compat<TcpStream>>) -> Result<String> {
    //     let query = "SELECT @@version";
    //     let stream = client.query(query, &[]).await?;
    //     let row = stream.into_row().await?.ok_or_else(|| anyhow!("No version info"))?;
    //     let version: &str = row.get(0).ok_or_else(|| anyhow!("Failed to get version"))?;
    //     Ok(version.to_string())
    // }
}


// #[tokio::test]
// async fn test_mssql_brute() {

//     let proxy_details = ProxyDetails {
//         enabled: false,
//         host: String::from("127.0.0.1"),
//         password: Option::None,
//         port: String::from("7897"),
//         username: Option::None,
//     };

//     // 使用 ProxyDetails 实例创建一个 ProxyConfig 实例
//     let proxy_config = ProxyConfig {
//         socks5: proxy_details,
//     };

//     let result = MssqlBrute::check_weak_pass(
//         "127.0.0.1",
//         1433,
//         "sa".to_string(),
//         "root@123.".to_string(),
//         proxy_config,
//         5,
//     ).await.unwrap();
//     println!("{:?}", result);
// }
