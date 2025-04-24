use crate::utils::parser::parse_user_pass_form_file;
use crate::utils::tcp_connect::connect;
use std::net::ToSocketAddrs;
use futures::stream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use futures::StreamExt;
use crate::ProxyConfig;
use anyhow::{anyhow, Error, Result};

use super::BruteResult;

pub struct RedisBrute {
    host: String,
    port: u16,
    timeout: u32,
}


impl RedisBrute {
    pub fn new(host: String, port: u16, timeout: u32) -> Self {
        Self {
            host,
            port,
            timeout,
        }
    }

        // 检查Redis认证
        pub async fn check_auth(
            host: String,
            port: u16,
            _username: String,
            password: String,
            proxy_config: ProxyConfig,
            _username_suffix: String,
            _retries: u32,
            timeout: u32,
            _single_account: bool,) -> anyhow::Result<Vec<BruteResult>,Error> {
            // 创建RedisBrute实例
            let redis = RedisBrute::new(
                host.to_string(),
                port,
                timeout,
            );

            let mut brute_result = Vec::new();

            // 尝试无认证连接
            match redis.try_no_auth(proxy_config.clone()).await {
                // 无认证连接成功
                anyhow::Result::Ok(true) => {
                    // 打印成功信息
                    println!("[+] Redis no authentication required - {}:{}", redis.host, redis.port);
                    brute_result.push(BruteResult::new(1,redis.host.clone(),"Redis".to_string(),redis.port.into(),String::new(), 
                    "no authentication required".to_string(), "Redis server".to_string(), "3".to_string()));
                    return Ok(brute_result);
                }
                // // 需要认证
                anyhow::Result::Ok(false) => {
                    // 打印需要认证信息
                    println!("[-] Redis requires authentication - {}:{}", redis.host, redis.port);
                    let result = redis.check_weak_pass(password,proxy_config).await?;
                    if result.len() > 0 {
                        brute_result.extend(result);
                    }
                    return Ok(brute_result);
                }

                // 连接错误
                Err(e) => {
                    // 打印连接错误信息
                    println!("[-] Redis connection error - {}:{} - {}", redis.host, redis.port, e);
                    // 返回错误
                    return Err(e);
                }
            }

        }

        async fn check_weak_pass(
            &self,
            password_file: String,
            proxy_config: ProxyConfig,
        ) -> Result<Vec<BruteResult>,anyhow::Error> {
            let mut scan_result = Vec::new();

            let passwords = parse_user_pass_form_file(&password_file);
    
            // 将密码列表转换为并发流
            let password_stream = stream::iter(passwords);
            let mut concurrent_tasks = password_stream
                .map(|password:String| {
                    let host = self.host.clone();
                    let port = self.port;
                    let timeout = self.timeout;
                    let proxy_config = proxy_config.clone();
                    async move {
                        let redis = RedisBrute::new(
                            host.clone(),
                            port,
                            timeout,
                        );
                        let result = redis.try_login(&password, proxy_config).await;
                        (password, result)
                    }
                })
                .buffer_unordered(10);
    
            // 处理并发任务的结果
            while let Some((password, result)) = concurrent_tasks.next().await {
                match result {
                    anyhow::Result::Ok(true) => {
                        scan_result.push(BruteResult::new(1,self.host.clone(),"Redis".to_string(),self.port.into(),String::new(), 
                        password, "Redis server".to_string(), "3".to_string()));
                    }
                    anyhow::Result::Ok(false) => {
                        continue;
                        // return Ok(scan_result);
                    }
                    anyhow::Result::Err(e) => {
                        continue;
                    //   return Ok(scan_result)
                    }
                }
            }
            Ok(scan_result)
        }

        async fn try_login(&self, password: &str, proxy_config: ProxyConfig) -> Result<bool,anyhow::Error> {
            let addr = format!("{}:{}", self.host, self.port);
            let mut stream = connect(
                addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Invalid address"))?,
                proxy_config,
                self.timeout as u32
            ).await?;

            // 发送 AUTH 命令
            let auth_command = format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", password.len(), password);
            stream.write_all(auth_command.as_bytes()).await?;

            // 读取 AUTH 响应
            let mut response = vec![0u8; 1024];
            let n = match timeout(Duration::from_secs(self.timeout as u64), stream.read(&mut response)).await {
                anyhow::Result::Ok(anyhow::Result::Ok(n)) => n,
                anyhow::Result::Ok(Err(e)) => return Err(anyhow!("Read error: {}", e)),
                Err(_) => return Err(anyhow!("Read timeout")),
            };

            let response_str = String::from_utf8_lossy(&response[..n]);
            println!("AUTH response: {}", response_str);

            // 检查认证结果
            if response_str.starts_with("+OK") {
                println!("Redis authentication successful - {}:{} password: {}", self.host, self.port, password);
                Ok(true)
            } else {
                println!("Redis authentication failed - {}:{} password: {}", self.host, self.port, password);
                Ok(false)
            }
        }
    

        async fn try_no_auth(&self, proxy_config: ProxyConfig) -> Result<bool, anyhow::Error> {
            let addr = format!("{}:{}", self.host, self.port);

            println!("[-] Trying no authentication - {}:{}", self.host, self.port);
            
            // 使用 tcp_connect 模块建立代理连接
            let mut tcp_stream: TcpStream = connect(
                addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Invalid address"))?,
                proxy_config,
                self.timeout as u32
            ).await?;

            // Redis PING 命令的RESP协议
            let ping_command = "*1\r\n$4\r\nPING\r\n";

            // 发送 PING 命令到 Redis
            tcp_stream.write_all(ping_command.as_bytes()).await?;

            // 准备接收响应，使用固定大小缓冲区
            let mut response = vec![0u8; 1024];
            
            // 设置读取超时
            match timeout(Duration::from_secs(self.timeout as u64), tcp_stream.read(&mut response)).await {
                anyhow::Result::Ok(anyhow::Result::Ok(n)) => {
                    let response_str = String::from_utf8_lossy(&response[..n]);
                    // 判断 PING 是否成功
                    if response_str.contains("+PONG") {
                        println!("[+] Redis no authentication required - {}:{}", self.host, self.port);
                        Ok(true)
                    } else if response_str.contains("-NOAUTH") {
                        println!("[-] Redis requires authentication - {}:{}", self.host, self.port);
                        Ok(false)
                    } else {
                        println!("[-] Unexpected response: {}", response_str);
                        Ok(false)
                    }
                },
                anyhow::Result::Ok(Err(e)) => Err(anyhow!("Read error: {}", e)),
                Err(_) => Err(anyhow!("Read timeout"))
            }
        }


}


// #[cfg(test)]
// mod tests {

//         use crate::ProxyDetails;

//         use super::*;
//         #[tokio::test]
//         async fn test_check_auth() {
            
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

//             let host = "127.0.0.1";
//             let port = 6379;
//             let username_file = "".to_string();
//             let password_file = "d:\\安全工具\\字典\\fuzzDicts-master\\fuzzDicts-master\\passwordDict\\ServiceWeakPass\\ssh弱口令\\ssh-pass.txt".to_string();
//             let single_account = false;
//             let timeout = 5;

//             let redis = RedisBrute::new(
//                 host.to_string(),
//                 port,
//                 timeout,
//             );
//         //    let result = redis.check_weak_pass(password_file,(proxy_config.clone()).await.unwrap();
//         //    println!("{:?}",result);

//             let result = RedisBrute::check_auth("127.0.0.1", 6379, "".to_string(), password_file, proxy_config, false, 5).await.unwrap();
//             println!("{:?}",result);

//         }
// }



