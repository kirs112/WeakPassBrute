use std::time::Duration;
use anyhow::{Result, anyhow};
use tokio_postgres::{NoTls};
use anyhow::Error as PgError;
use futures::stream::{self, StreamExt};

use crate::{utils::parser::parse_user_pass_form_file, ProxyConfig};

use super::BruteResult;

#[derive(Clone)]
pub struct PostgresqlBrute {
    host: String,
    port: u16,
    timeout: Duration,
}

impl PostgresqlBrute {
    pub fn new(host: String, port: u16, timeout: Duration) -> Self {
        Self {
            host,
            port,
            timeout,
        }
    }

    pub async fn run_brute(
        host: String,
        port: u16,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        _username_suffix: String,
        _retries: u32,
        timeout: u32,
        _single_account: bool,
    ) -> Result<Vec<BruteResult>, PgError> {
        let mut pg_brute_result:Vec<BruteResult> = Vec::new();

        let pg_brute = PostgresqlBrute::new(
            host.clone(),
            port,
            Duration::from_secs(timeout as u64),
        );
        // 获取用户名列表
        // let usernames = if let Some(file) = username_file {
        //     read_lines(&file)?
        // } else {
        //     get_usernames("mssql")
        // };
        let usernames = parse_user_pass_form_file(&username);

        // 尝试每个用户名和密码组合
        for username in usernames {
            // 获取密码列表
            let passwords = parse_user_pass_form_file(&password);

            // 将密码列表转换为并发流
            let password_stream = stream::iter(passwords);
            let mut concurrent_tasks = password_stream
                .map(|password| {
                    let pg = pg_brute.clone();
                    let username = username.clone();
                    async move {
                        let result = pg.check_auth(&username, &password).await;
                        (password, result)
                    }
                })
                .buffer_unordered(10);

            // 处理并发任务的结果
            while let Some((password, result)) = concurrent_tasks.next().await {
                match result {
                    Ok(true) => {
                        // println!("[+] PostgreSQL auth success - {}:{} {}/{}", host, port, username, password);
                        pg_brute_result.push(
                            BruteResult::new(1,host.clone(),"PostgreSQL".to_string(),port.into(),username.clone(), 
                        password, "PostgreSQL server".to_string(), "3".to_string())
                    );
                        return Ok(pg_brute_result);
                    }
                    Ok(false) => continue,
                    Err(e) => {
                        // println!("[-] PostgreSQL login error - {}:{} {}/{} - {:?}",
                        //     host, port, username, password, e);
                        continue;
                    }
                }
            }
        }
        Ok(pg_brute_result)
    }

    async fn check_auth(&self, username: &str, password: &str) -> Result<bool> {
        let connect_str = format!(
            "host={} port={} user={} password={} connect_timeout={}",
            self.host,
            self.port,
            username,
            password,
            self.timeout.as_secs()
        );

        match tokio_postgres::connect(&connect_str, NoTls).await {
            Ok((client, connection)) => {
                // 在后台运行连接
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        eprintln!("Connection error: {}", e);
                    }
                });

                // output::success(&format!(
                //     "[+] PostgreSQL auth success - {}:{} {}:{}",
                //     self.host, self.port, username, password
                // ));
                Ok(true)
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("password authentication failed") || 
                   error_str.contains("authentication failed") {
                    // println!(
                    //     "[-] PostgreSQL auth failed - {}:{} {}:{}",
                    //     self.host, self.port, username, password
                    // );
                    Ok(false)
                } else {

                    Err(anyhow!("PostgreSQL connection error: {}", e))
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
//     async fn test_postgresql_auth() {
//         // let brute = PostgresqlBrute::new(
//         //     "localhost".to_string(),
//         //     5432,
//         //     Duration::from_secs(5),
//         // );
//         // let proxy_details = ProxyDetails {
//         //     enabled: false,
//         //     host: String::from("127.0.0.1"),
//         //     password: Option::None,
//         //     port: String::from("7897"),
//         //     username: Option::None,
//         // };
    
//         // 使用 ProxyDetails 实例创建一个 ProxyConfig 实例
//         let proxy_config = ProxyConfig {
//             socks5: ProxyDetails {
//                 enabled: false,
//                 host: String::from("127.0.0.1"),
//                 password: Option::None,
//                 port: String::from("7897"),
//                 username: Option::None,
//             }
//         };

//         let result = PostgresqlBrute::run_brute("localhost", 5432, "postgres".to_string(), "root@123.".to_string(), 5, proxy_config).await;
//         println!("Brute force result: {:?}", result);
//     }
// }
