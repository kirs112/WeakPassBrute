

use anyhow::Error;
use futures::stream;
use crate::utils::parser::parse_user_pass_form_file;
use crate::{utils::tcp_connect::connect, ProxyConfig};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use anyhow::Result;
use tokio::time::Duration;
use super::BruteResult;
use anyhow::anyhow;
use futures::StreamExt;

pub struct FtpBrute {
    host: String,
    port: u16,
    username: String,
    password: String,
    timeout: u32,
}

impl FtpBrute {
    pub fn new(host: String, port: u16, username: String, password: String,timeout: u32) -> Self {
        Self {
            host,
            port,
            username,
            password,
            timeout: timeout,
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
        single_account: bool,
    ) -> anyhow::Result<Vec<BruteResult>,Error> {
    
        let mut brute_result = Vec::new();
    
        // 首先尝试匿名登录
        let anon_check = FtpBrute::new(
            host.clone(),
            port,
            "anonymous".to_string(),
            "anonymous".to_string(),
            timeout,
        );
    
        let check_anonmouse_vuln =  anon_check.check_anonmous(proxy_config.clone()).await?;
        if check_anonmouse_vuln {
             brute_result.push(BruteResult::new(1,anon_check.host.clone(),"FTP".to_string(), port.into(), "anonymous".to_string(),
              "anonymous".to_string(), "220 FTP Server Ready".to_string(), "3".to_string()));
            if single_account {
                return Ok(brute_result);
            }
        }
    
        let usernames = parse_user_pass_form_file(&username);
        let passwords = parse_user_pass_form_file(&username);
    
        // 设置并发数
        const CONCURRENT_LIMIT: usize = 50;
    
        for username in usernames {
            // 将密码列表转换为并发流
            let password_stream = stream::iter(passwords.clone());
            let mut concurrent_tasks = password_stream
                .map(|password| {
                    let host = host.clone();
                    let username = username.clone();
                    let proxy_config = proxy_config.clone();
                    async move {
                        let brute = FtpBrute::new(
                            host,
                            port,
                            username,
                            password,
                            timeout,
                        );
                        brute.run_brute(proxy_config).await
                    }
                })
                .buffer_unordered(CONCURRENT_LIMIT);
            // 处理并发任务的结果
            while let Some(result) = concurrent_tasks.next().await {
                match result {
                    Result::Ok(results) => {
                        if !results.is_empty() {
                            // println!("Found valid credentials: {:?}", results);  // 添加调试输出
                            brute_result.extend(results);  // 使用 extend 替代 append
                            if single_account {
                                return Result::Ok(brute_result);
                            }
                        }
                    },
                    Result::Err(e) => {
                        println!("Error during brute force: {:?}", e);  // 添加错误输出
                        continue;
                    }
                }
            }
        }
        // println!("FTP Brute Force1{:?}",brute_result);
        Ok(brute_result)
    }

    pub async fn run_brute(&self, proxy_config: ProxyConfig) -> Result<Vec<BruteResult>, anyhow::Error> {
        let mut brute_result = Vec::new();
        let target = format!("{}:{}", self.host, self.port);

        let mut stream = connect((&target).parse().unwrap(),proxy_config,self.timeout as u32).await?;
        stream.set_nodelay(true).unwrap();

        // 读取初始欢迎消息
        let mut response = [0; 1024];
        if let Err(_) = tokio::time::timeout(
            Duration::from_secs(self.timeout as u64),
            stream.read(&mut response)
        ).await {
            return Err(anyhow!("Read timeout"));
        }
        let welcome_msg = String::from_utf8_lossy(&response);
        // println!("Welcome message: {}", welcome_msg);  // 添加欢迎消息调试
                    // 处理 banner，只保留有效内容
        let banner = welcome_msg
                .split('\0')  // 按 null 字符分割
                .next()       // 取第一部分
                .unwrap_or("")
                .trim()       // 去除两端空白
                .to_string();

        // 发送用户名
        let user_cmd = format!("USER {}\r\n", self.username);
        if let Err(_) = tokio::time::timeout(
            Duration::from_secs(self.timeout as u64),
            stream.write_all(user_cmd.as_bytes())
        ).await {
            return Err(anyhow!("Write timeout"));
        }
        
        // 读取用户名响应
        let mut user_response = [0; 1024];
        if let Err(_) = tokio::time::timeout(
            Duration::from_secs(self.timeout as u64),
            stream.read(&mut user_response)
        ).await {
            return Err(anyhow!("Read timeout"));
        }
        let user_resp = String::from_utf8_lossy(&user_response);
        // println!("User response: {}", user_resp);  // 添加用户名响应调试

        // 发送密码
        let pass_cmd = format!("PASS {}\r\n", self.password);
        if let Err(_) = tokio::time::timeout(
            Duration::from_secs(self.timeout as u64),
            stream.write_all(pass_cmd.as_bytes())
        ).await {
            return Err(anyhow!("Write timeout"));
        }

        // 读取密码响应
        let mut pass_response = [0; 1024];
        if let Err(_) = tokio::time::timeout(
            Duration::from_secs(self.timeout as u64),
            stream.read(&mut pass_response)
        ).await {
            return Err(anyhow!("Read timeout"));
        }
        let pass_resp = String::from_utf8_lossy(&pass_response);
        // println!("Password response: {}", pass_resp);  // 添加密码响应调试

        // 检查登录结果
        if pass_resp.contains("230") || pass_resp.contains("Login successful") {
            // println!("Login successful with {}:{}", self.username, self.password);
            brute_result.push(BruteResult::new(
                1,
                self.host.clone(),
                "FTP".to_string(),
                self.port.into(),
                self.username.clone(),
                self.password.clone(),
                banner,
                "3".to_string()
            ));
            Ok(brute_result)
        } else {
            Ok(Vec::new())
        }
    }


    async fn check_anonmous(&self,proxy_config: ProxyConfig) -> anyhow::Result<bool, Error> {
        let target = format!("{}:{}", self.host, self.port);

        let mut stream = connect((&target).parse().unwrap(),proxy_config,self.timeout as u32).await?;
        stream.set_nodelay(true).unwrap();

        let mut response = [0; 1024];
        stream.read(&mut response).await.unwrap();

                // Try anonymous login
        stream.write_all(b"USER anonymous\r\n").await.unwrap();
        stream.read(&mut response).await.unwrap();

        stream.write_all(b"PASS anonymous\r\n").await.unwrap();
        let size = stream.read(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response[..size]);

        if response_str.contains("230") {
                Ok(true)
        } else {
            Ok(false)
        }
        
    }

}




// #[cfg(test)]
// mod tests {
//     use crate::ProxyDetails;

//     use super::*;
//     #[tokio::test]
//    async fn test_check_weak_pass() {

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

//         let host = "127.0.0.1";
//         let port = 21;
//         let username_file = "d:\\安全工具\\字典\\fuzzDicts-master\\fuzzDicts-master\\passwordDict\\ServiceWeakPass\\ssh弱口令\\ssh-user.txt".to_string();
//         let password_file = "d:\\安全工具\\字典\\fuzzDicts-master\\fuzzDicts-master\\passwordDict\\ServiceWeakPass\\ssh弱口令\\ssh-pass.txt".to_string(); 
//         // let proxy_config = ProxyConfig::new(None,None,None);
//         let single_account = false;
//         let timeout = 10;
//         let result = FtpBrute::check_weak_pass(host, port, username_file, password_file, proxy_config, single_account, timeout).await.unwrap();
//         println!("{:?}",result);
//     }


// }
