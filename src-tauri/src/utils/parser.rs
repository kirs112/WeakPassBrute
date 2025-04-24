use std::{collections::VecDeque, str::FromStr, fs};
use std::net::{IpAddr, Ipv4Addr};
use anyhow::{Result, Error};
use std::path::Path;
use std::fs::File;
use std::io::{self, BufRead};

/// 解析目标，可以是文件路径、IP、IP范围或CIDR
pub fn parse_targets(target: &str) -> Vec<IpAddr> {
    if is_valid_path(target) {
        return parse_targets_from_file(target).unwrap_or_default();
    }

    if target.contains('-') {
        return parse_ip_range(target).unwrap_or_default();
    } else if target.contains('/') {
        return parse_cidr(target).unwrap_or_default();
    }

    parse_single_ip(target).ok().into_iter().collect()
}

pub fn parse_user_pass_form_file(user_pass: &str) -> Vec<String> {
    if is_valid_path(user_pass) {
        return parse_user_pass_from_file(user_pass).unwrap_or_default();
    }

    return vec![user_pass.to_string()];

}

/// 判断字符串是否为有效路径
fn is_valid_path(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn parse_user_pass_from_file(file_path: &str) -> Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);

    let lines: Vec<String> = reader
        .lines()
        .collect::<Result<_, _>>()?; // 处理错误

    Ok(lines)
}


/// 从文件中解析IP地址
pub fn parse_targets_from_file(file_path: &str) -> Result<Vec<IpAddr>> {
    let content = fs::read_to_string(file_path)?;
    Ok(content.lines()
        .filter(|line| !line.trim().is_empty())  // 过滤空行
        .filter_map(|line| parse_single_ip(line.trim()).ok())  // 只保留成功解析的IP
        .collect())
}

/// 解析IP范围 (如 192.168.1.1-255)
fn parse_ip_range(range: &str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(Error::msg("Invalid IP range format"));
    }

    let base_ip = parts[0];
    let end_num: u8 = parts[1].parse().map_err(|_| Error::msg("Invalid IP range end number"))?;

    let ip_parts: Vec<&str> = base_ip.split('.').collect();
    if ip_parts.len() != 4 {
        return Err(Error::msg("Invalid IP address format"));
    }

    let start_num: u8 = ip_parts[3].parse().map_err(|_| Error::msg("Invalid IP address format"))?;

    for i in start_num..=end_num {
        let ip_str = format!("{}.{}.{}.{}", ip_parts[0], ip_parts[1], ip_parts[2], i);
        ips.push(parse_single_ip(&ip_str)?);
    }

    Ok(ips)
}

/// 解析CIDR格式 (如 192.168.1.0/24)
fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::msg("Invalid CIDR format"));
    }

    let base_ip = parse_single_ip(parts[0])?;
    let prefix: u8 = parts[1].parse().map_err(|_| Error::msg("Invalid CIDR prefix"))?;

    if prefix > 32 {
        return Err(Error::msg("Invalid CIDR prefix (must be <= 32)"));
    }

    if let IpAddr::V4(ipv4) = base_ip {
        let ip_u32 = u32::from(ipv4);
        let mask = !(!0u32 >> prefix);
        let network = ip_u32 & mask;
        let mut ips = Vec::new();

        for i in 0..(1 << (32 - prefix)) {
            let new_ip = network | i;
            let octets = new_ip.to_be_bytes();
            ips.push(IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])));
        }
        Ok(ips)
    } else {
        Err(Error::msg("Only IPv4 is supported"))
    }
}

/// 解析单个IP地址字符串
/// 
/// # Arguments
/// * `ip` - IP地址字符串
///
/// # Returns
/// * `Ok(IpAddr)` - 成功解析的IP地址
/// * `Err` - 解析失败的错误信息
///
/// # Examples
/// ```
/// let ip = parse_single_ip("192.168.1.1").unwrap();
/// ```
fn parse_single_ip(ip: &str) -> Result<IpAddr> {
    let ip = ip.trim();
    if ip.is_empty() {
        return Err(Error::msg("IP address string is empty"));
    }
    
    IpAddr::from_str(ip).map_err(|e| Error::msg(format!("Failed to parse IP address '{}': {}", ip, e)))
}

/// 判断字符串是否为Windows路径格式（以盘符开头，如 C:\ 或 c:/）
/// 
/// # Arguments
/// * `s` - 要检查的字符串
///
/// # Returns
/// * `bool` - 如果字符串是Windows路径格式则返回true，否则返回false
///
/// # Examples
/// ```
/// assert!(is_letter_with_colon("C:\\Users\\file.txt"));
/// assert!(is_letter_with_colon("c:/Users/file.txt"));
/// ```
pub fn is_letter_with_colon(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    
    let first_char = s.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() {
        return false;
    }

    // 检查第二个字符是否为冒号
    if s.chars().nth(1) != Some(':') {
        return false;
    }

    // 检查冒号后是否跟着路径分隔符（/ 或 \）
    if s.len() > 2 {
        let third_char = s.chars().nth(2).unwrap();
        return third_char == '/' || third_char == '\\';
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_letter_with_colon() {
        // 有效路径
        assert!(is_letter_with_colon("C:\\Users\\file.txt"));
        assert!(is_letter_with_colon("c:/Users/file.txt"));
        assert!(is_letter_with_colon("D:\\"));
        assert!(is_letter_with_colon("e:/"));
        
        // 无效路径
        assert!(!is_letter_with_colon("1:\\Users\\file.txt")); // 数字
        assert!(!is_letter_with_colon("c:Users\\file.txt"));   // 缺少分隔符
        assert!(!is_letter_with_colon("c"));                   // 太短
        assert!(!is_letter_with_colon(""));                    // 空字符串
        assert!(!is_letter_with_colon("192.168.1.1:80"));     // IP:端口
    }
}
