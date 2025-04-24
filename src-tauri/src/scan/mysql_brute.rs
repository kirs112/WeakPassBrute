use std::time::Duration;
use anyhow::{Result, anyhow};
use futures::stream::{self, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::utils::parser::parse_user_pass_form_file;
use crate::{utils::tcp_connect::connect, ProxyConfig};
use std::net::ToSocketAddrs;
use super::BruteResult;
use sha1::{Sha1, Digest};

#[derive(Debug,Clone)]
pub struct MysqlBrute {
    host: String,
    port: u16,
    timeout: u32,
}

impl MysqlBrute {
    pub fn new(host: String, port: u16, timeout: u32) -> Self {
        Self {
            host,
            port,
            timeout,
        }
    }

    fn read_packet(data: &[u8]) -> Result<(usize, &[u8])> {
        if data.len() < 4 {
            return Err(anyhow!("Packet too short"));
        }
        let length = (data[0] as usize) | ((data[1] as usize) << 8) | ((data[2] as usize) << 16);
        Ok((length, &data[4..]))
    }

    fn scramble_password(password: &str, salt: &[u8]) -> Vec<u8> {
        if password.is_empty() {
            return Vec::new();
        }

        // 确保只使用20字节的salt（去掉末尾的null字节）
        let salt = &salt[..20];
        // println!("Using salt for scramble: {:02x?}", salt);

        // Stage1: SHA1(password)
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let stage1 = hasher.finalize();

        // Stage2: SHA1(Stage1)
        let mut hasher = Sha1::new();
        hasher.update(&stage1);
        let stage2 = hasher.finalize();

        // Stage3: SHA1(salt + Stage2)
        let mut hasher = Sha1::new();
        hasher.update(salt);
        hasher.update(&stage2);
        let stage3 = hasher.finalize();

        // XOR stage1 with stage3
        let mut result = vec![0u8; 20];
        for i in 0..20 {
            result[i] = stage1[i] ^ stage3[i];
        }

        // println!("Password being hashed: {}", password);
        // println!("Stage1 (SHA1(password)): {:02x?}", stage1);
        // println!("Stage2 (SHA1(Stage1)): {:02x?}", stage2);
        // println!("Stage3 (SHA1(salt+Stage2)): {:02x?}", stage3);
        // println!("Final scrambled: {:02x?}", result);

        result
    }

    async fn try_login(&self, username: &str, password: &str, proxy_config: ProxyConfig) -> Result<bool> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = connect(
            addr.to_socket_addrs()?.next().ok_or_else(|| anyhow!("Invalid address"))?,
            proxy_config,
            self.timeout as u32
        ).await?;

        // 读取初始握手包
        let mut initial_packet = vec![0u8; 1024];
        let n = stream.read(&mut initial_packet).await?;
        if n < 4 {
            return Err(anyhow!("Invalid handshake packet"));
        }

        // println!("Initial packet: {:?}", &initial_packet[..n]);

        // 解析握手包
        let (packet_len, packet_data) = Self::read_packet(&initial_packet)?;
        if packet_len + 4 > n {
            return Err(anyhow!("Incomplete packet"));
        }

        // 检查协议版本
        let protocol_version = packet_data[0];
        if protocol_version != 10 {
            return Err(anyhow!("Unsupported protocol version"));
        }

        // 提取服务器版本字符串
        let mut pos = 1;
        while pos < packet_data.len() && packet_data[pos] != 0 {
            pos += 1;
        }
        let server_version = String::from_utf8_lossy(&packet_data[1..pos]);
        // println!("Server version: {}", server_version);
        pos += 1;  // 跳过NULL终止符

        // 提取connection id (4 bytes)
        let connection_id = u32::from_le_bytes([
            packet_data[pos], packet_data[pos + 1],
            packet_data[pos + 2], packet_data[pos + 3]
        ]);
        // println!("Connection ID: {}", connection_id);
        pos += 4;

        // 提取完整的salt (auth plugin data)
        let mut salt = Vec::with_capacity(20);
        // 第一部分salt (8字节)
        salt.extend_from_slice(&packet_data[pos..pos+8]);
        pos += 8;
        pos += 1;  // 跳过filler

        // 读取capability flags
        let mut capabilities = [0u8; 2];
        capabilities.copy_from_slice(&packet_data[pos..pos+2]);
        // let capabilities = u16::from_le_bytes(capabilities);
        // println!("Server capabilities (raw): {:x}", capabilities);
        // println!("Using capabilities: {:x}", server_capabilities);
        pos += 2;

        // 读取charset
        let charset = packet_data[pos];
        // println!("Server charset: {:x}", charset);
        pos += 1;

        // 读取server status
        let mut status = [0u8; 2];
        status.copy_from_slice(&packet_data[pos..pos+2]);
        // let status = u16::from_le_bytes(status);
        // println!("Server status: {:x}", status);
        pos += 2;

        // 跳过capability flags part 2
        pos += 2;

        // 读取auth plugin data len
        let auth_plugin_data_len = packet_data[pos] as usize;
        // println!("Auth plugin data len: {}", auth_plugin_data_len);
        pos += 1;

        // 跳过reserved
        pos += 10;

        // 读取剩余的salt
        if auth_plugin_data_len > 8 {
            let remaining = auth_plugin_data_len - 8;
            salt.extend_from_slice(&packet_data[pos..pos+remaining]);
        }

        // println!("Complete salt: {:?}", salt);

        // 读取auth plugin name
        pos += 12;  // 跳过剩余的auth plugin data
        let mut auth_plugin_name = Vec::new();
        while pos < packet_data.len() && packet_data[pos] != 0 {
            auth_plugin_name.push(packet_data[pos]);
            pos += 1;
        }
        let auth_plugin_name = String::from_utf8_lossy(&auth_plugin_name);
        // println!("Auth plugin name: {}", auth_plugin_name);

        // 定义必要的 capability flags
        const CLIENT_PROTOCOL_41: u32 = 0x00000200;
        const CLIENT_SECURE_CONNECTION: u32 = 0x00008000;
        // const CLIENT_CONNECT_WITH_DB: u32 = 0x00000008;
        const CLIENT_PLUGIN_AUTH: u32 = 0x00080000;
        const CLIENT_LONG_PASSWORD: u32 = 0x00000001;


        // let server_capabilities = u32::from(capabilities);
        
        // 构建认证包
        let mut auth_packet = Vec::new();

        // Client capabilities flags (4 bytes, little-endian)
        let client_flags = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_LONG_PASSWORD;
        auth_packet.extend_from_slice(&client_flags.to_le_bytes());

        // Max packet size (4 bytes, little-endian)
        let max_packet_size: u32 = 16 * 1024 * 1024;
        auth_packet.extend_from_slice(&max_packet_size.to_le_bytes());

        // Character set (1 byte)
        auth_packet.push(charset);

        // Reserved 23 bytes of 0
        auth_packet.extend_from_slice(&[0u8; 23]);

        // Username
        auth_packet.extend_from_slice(username.as_bytes());
        auth_packet.push(0);  // NULL terminator

        // Password hash length and value
        let scrambled = Self::scramble_password(password, &salt[..20]); // 只使用前20字节的salt
        auth_packet.push(20u8);  // 固定使用20字节长度
        auth_packet.extend_from_slice(&scrambled);

        // Auth plugin name
        auth_packet.extend_from_slice(b"mysql_native_password");
        auth_packet.push(0);  // NULL terminator

        // 构建完整数据包
        let length = auth_packet.len();
        let mut packet = Vec::new();
        packet.extend_from_slice(&(length as u32).to_le_bytes()[0..3]);
        packet.push(1);  // Sequence number
        packet.extend_from_slice(&auth_packet);

        // println!("Auth packet length: {}", length);
        // println!("Complete auth packet: {:02x?}", packet);

        // 发送认证包
        stream.write_all(&packet).await?;

        // 读取响应
        let mut response = vec![0u8; 1024];
        let n = stream.read(&mut response).await?;
        
        // println!("Response packet: {:?}", &response[..n]);

        if n >= 5 {
            match response[4] {
                0x00 => {
                    // println!("[+] MySQL login success - {}:{} {}/{}", 
                    //     self.host, self.port, username, password);
                    Ok(true)
                },
                0xFF => {
                    // let error_code = u16::from_le_bytes([response[5], response[6]]);
                    // let error_message = String::from_utf8_lossy(&response[7..n]);
                    // println!("[-] MySQL login failed - Error code: {}, Message: {}", 
                    //     error_code, error_message);
                    //     println!("[-] MySQL login failed - {}:{} {}/{}", 
                    //     self.host, self.port, username, password);
                    Ok(false)
                },
                _ => Ok(false)
            }
        } else {
            Ok(false)
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
    ) -> Result<Vec<BruteResult>> {
        let mut brute_results = Vec::new();
        let usernames = parse_user_pass_form_file(&username);

        for username in usernames {
            let passwords = parse_user_pass_form_file(&password);
            
            let password_stream = stream::iter(passwords);
            let mut concurrent_tasks = password_stream
                .map(|password| {
                    let username = username.clone();
                    let proxy_config = proxy_config.clone();
                    let brute = MysqlBrute::new(
                        host.clone(),
                        port,
                        timeout,
                    );
                    async move {
                        let result = brute.try_login(&username, &password, proxy_config).await;
                        (username, password, result)
                    }
                })
                .buffer_unordered(10);

            while let Some((username, password, result)) = concurrent_tasks.next().await {
                match result {
                    Ok(true) => {
                        // let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        brute_results.push(BruteResult::new(
                            1,
                            host.clone(),
                            "MySQL".to_string(),
                            port as i32,
                            username,
                            password,
                            "MySQL server".to_string(),
                            "3".to_string(),
                        ));
                    }
                    Ok(false) => continue,
                    Err(_e) => {
                        // println!("[-] Error during MySQL brute force: {}", e);
                        continue;
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
//     async fn test_mysql_brute() -> Result<()> {
//         let proxy_config = ProxyConfig {
//             socks5: ProxyDetails {
//                 enabled: false,
//                 host: String::new(),
//                 port: String::new(),
//                 username: None,
//                 password: None,
//             }
//         };

//         let brute = MysqlBrute::new(
//             "127.0.0.1".to_string(),
//             3306,
//             5,
//         );

//         let result = brute.check_weak_pass(
//             "d:\\安全工具\\字典\\fuzzDicts-master\\fuzzDicts-master\\passwordDict\\ServiceWeakPass\\ssh弱口令\\ssh-user.txt".to_string(),
//             "d:\\安全工具\\字典\\fuzzDicts-master\\fuzzDicts-master\\passwordDict\\ServiceWeakPass\\ssh弱口令\\ssh-pass.txt".to_string(),
//             proxy_config,
//         ).await?;

//         println!("Brute force results: {:?}", result);
//         Ok(())
//     }
// }
