mod ftp_brute;
mod redis_brute;
mod ssh_brute;
mod rdp_brute;
mod mysql_brute;
mod mssql_brute;
mod smb_brute;
mod oracle_brute;
mod pgsql_brute;
// mod memcache_brute;
mod ms17010;

use std::{future::Future, net::{IpAddr, SocketAddr}, pin::Pin};
use crate::{utils::tcp_connect::connect, ProxyConfig,ProxyDetails};



// 定义爆破结果的结构体，与前端的BruteResult接口对应
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BruteResult {
    pub id: i32,
    pub ip: String,
    pub service: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    pub banner: String,
    pub time: String,
}


impl BruteResult {
    pub fn new(id: i32, ip: String, service: String, port: i32, username: String, password: String, banner: String, time: String) -> Self {
        BruteResult {
            id,
            ip,
            service,
            port,
            username,
            password,
            banner,
            time,
        }
    }
    
}

// 添加一个专门用于端口检测的函数
pub async fn check_port_open(addr: &IpAddr, port: u16, proxy_config: ProxyConfig,timeout: u32) -> bool {
    let socket_addr = SocketAddr::new(*addr, port as u16);
    
    match connect(socket_addr, proxy_config,timeout).await {
        Ok(_) => true,
        Err(_) => false
    }
}
pub type ScanResult<T> = anyhow::Result<T>;

// 定义 ServiceCheck 结构体
pub struct ServiceCheck {
    pattern: &'static str,
    handler: fn(ip: String,
        port: u16,
        // service_pattern: &str,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        retries: u32,
        timeout: u32,
        single_account: bool) -> Pin<Box<dyn Future<Output = Result<Vec<BruteResult>, anyhow::Error>> + Send>>,
}

impl ServiceCheck {
    // 修改执行方法返回 Vec<BruteResult>
    pub async fn execute(&self, 
        ip: String,
        port: u16,
        // service_pattern: &str,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        retries: u32,
        timeout: u32,
        single_account: bool,) -> Result<Vec<BruteResult>, anyhow::Error> {
        (self.handler)(ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account).await
    }

    pub fn get_pattern(&self) -> &str {
        self.pattern
    }
}

// 获取服务检查配置
pub fn get_service_checks() -> Vec<ServiceCheck> {
    vec![
        ServiceCheck {
            pattern: "mysql",
            handler: |
                ip: String,
                port: u16,
                // service_pattern: &str,
                username: String,
                password: String,
                proxy_config: ProxyConfig,
                username_suffix: String,
                retries: u32,
                timeout: u32,
                single_account: bool
                | {
                Box::pin(async move {
                    mysql_brute::MysqlBrute::check_weak_pass(ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account).await
                })
            },
        },
        ServiceCheck {
            pattern: "ftp",
            handler: |ip: String,
            port: u16,
            // service_pattern: &str,
            username: String,
            password: String,
            proxy_config: ProxyConfig,
            username_suffix: String,
            retries: u32,
            timeout: u32,
            single_account: bool| {
                Box::pin(async move {
                    ftp_brute::FtpBrute::check_weak_pass(ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account).await
                })
            },
        },
        ServiceCheck {
            pattern: "redis",
            handler: |ip: String,
        port: u16,
        // service_pattern: &str,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        retries: u32,
        timeout: u32,
        single_account: bool| {
                Box::pin(async move {
                    redis_brute::RedisBrute::check_auth(ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account).await
                })
            },
        },
        ServiceCheck {
            pattern: "postgresql",
            handler: |ip: String,
        port: u16,
        // service_pattern: &str,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        retries: u32,
        timeout: u32,
        single_account: bool| {
                Box::pin(async move {
                    pgsql_brute::PostgresqlBrute::run_brute(ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account).await
                })
            },
        },
        ServiceCheck {
            pattern: "ssh",
            handler: |ip: String,
        port: u16,
        // service_pattern: &str,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        retries: u32,
        timeout: u32,
        single_account: bool| {
                Box::pin(async move {
                    ssh_brute::SshBrute::check_weak_pass(ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account).await
                })
            },
        },
        ServiceCheck {
            pattern: "rdp",
            handler: |ip: String,
        port: u16,
        // service_pattern: &str,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        retries: u32,
        timeout: u32,
        single_account: bool| {
                Box::pin(async move {
                    rdp_brute::RdpBrute::check_weak_pass(ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account).await
                })
            },
        },
        ServiceCheck {
            pattern: "smb",
            handler: |ip: String,
        port: u16,
        // service_pattern: &str,
        username: String,
        password: String,
        proxy_config: ProxyConfig,
        username_suffix: String,
        retries: u32,
        timeout: u32,
        single_account: bool| {
                Box::pin(async move {
                    smb_brute::SmbBrute::check_weak_pass(
                        ip, port, username, password, proxy_config, username_suffix,retries,timeout,single_account
                    ).await
                })
            },
        },
    ]
}

// 修改扫描执行器返回 Vec<BruteResult>
pub async fn run_service_scan(
    ip: String,
    port: u16,
    service_pattern: &str,
    username: String,
    password: String,
    proxy_config: ProxyConfig,
    username_suffix: String,
    retries: u32,
    timeout: u32,
    single_account: bool,
) -> Result<Vec<BruteResult>, anyhow::Error> {
    let service = get_service_checks()
        .into_iter()
        .find(|check| check.get_pattern().eq_ignore_ascii_case(service_pattern))
        .ok_or_else(|| anyhow::anyhow!("Unsupported service: {}", service_pattern))?;

    service.execute(ip, port, username, password, proxy_config, username_suffix, retries, timeout, single_account).await
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_scan() {
            let proxy_details = ProxyDetails {
                enabled: false,
                host: String::from("127.0.0.1"),
                password: Option::None,
                port: String::from("7897"),
                username: Option::None,
            };
        
            // 使用 ProxyDetails 实例创建一个 ProxyConfig 实例
            let proxy_config = ProxyConfig {
                socks5: proxy_details,
            };


        let results = run_service_scan(
            "127.0.0.1".to_string(),
            3306,
            "mysql",
            "root".to_string(),
            "root123".to_string(),
            proxy_config,
            "".to_string(),
            3,
            10,
            false,
        ).await;
        
        match results {
            Ok(brute_results) => {
                for result in brute_results {
                    println!("Found credentials - Service: {}, Username: {}, Password: {}", 
                        result.service, result.username, result.password);
                }
            },
            Err(e) => println!("Scan failed: {}", e),
        }
    }

    
}
