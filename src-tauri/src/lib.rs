mod utils;
mod scan;

use scan::{check_port_open, run_service_scan, BruteResult};
use serde::{Deserialize,Serialize};
use tauri::{Manager,Emitter};
use tauri_plugin_fs::FsExt;
use utils::parser::{parse_targets,is_letter_with_colon};
use std::{collections::HashMap};


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        // 注册命令，使前端可以调用
        .invoke_handler(tauri::generate_handler![start_brute_force, stop_brute_force])
        .setup(|app| {
            let scope = app.fs_scope();
            let _ = scope.allow_directory("*", true);
            let _ = scope.allow_file("*");
            #[cfg(debug_assertions)]
            app.get_webview_window("main").expect("Webview window not found");
            Ok(())
        })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

#[derive(Serialize, Deserialize, Debug,Clone)]
struct ProxyConfig {
    socks5: ProxyDetails,
}

#[derive(Serialize, Deserialize, Debug,Clone)]
struct ProxyDetails {
    enabled: bool,
    host: String,
    password: Option<String>,
    port: String,
    username: Option<String>,
}

// 全局状态，用于控制爆破任务的运行状态
static mut BRUTE_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// 导出函数，使其可以被main.rs导入
#[tauri::command]
async fn start_brute_force(
    app_handle: tauri::AppHandle,
    target: String,
    single_account: bool,
    port_check: bool,
    username: String,
    password: String,
    username_suffix: String,
    // threads: u32,
    timeout: u32,
    retries: u32,
    selected_services: Vec<String>,
    proxy_config: serde_json::Value,
    port_settings: HashMap<String, String>,
) -> Result<Vec<BruteResult>, String> {
    // println!("{}",target);
    // 设置运行状态为 true
    unsafe {
        BRUTE_RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    let proxy_config: ProxyConfig = serde_json::from_value(proxy_config).map_err(|e| e.to_string())?;


    let mut results: Vec<BruteResult> = Vec::new();
    let mut port:u16 = 0;

    // 解析目标IP地址
    let ip = if is_letter_with_colon(&target) {
        // 如果是路径格式(如 "c:path/to/file")，保持原样
        target
    } else if target.contains(':') {
        if let Some((_, p)) = target.split_once(':') {
                    port = p.parse::<u16>().unwrap_or(0);
                }
        // 如果包含冒号但不是路径格式(如 "192.168.1.1:80")，取冒号前的部分
        target.split(':').next().unwrap_or(&target).to_string()
    } else {
        target
    };

    let targets = parse_targets(&ip);
    if targets.is_empty() {
        return Err("Invalid target".to_string());
    }


    let mut err_msg:Vec<String> = Vec::new();

    // 遍历每个目标IP地址，进行爆破
    for target in targets {

        // 遍历用户选择的每个服务，进行爆破   
        for service in selected_services.iter(){
            // println!("service: {}",service);
            if !unsafe { BRUTE_RUNNING.load(std::sync::atomic::Ordering::SeqCst) } {
                return Err("".to_string()); // 如果运行状态为false
            } 

            // 检查端口是否开放
            if port_check {
               if port == 0 {
                   port =  port_settings.get(service)
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(0);
                };

                if !check_port_open(&target, port,proxy_config.clone(),timeout).await {
                    let error_msg = format!("Ip {} Port :{} is not open", target, port);
                    // 发送事件到前端
                    err_msg.push(error_msg.clone());
                    app_handle.emit("port_check_result", error_msg).unwrap_or_default();
                    continue;
                }
            }
    
            let result = run_service_scan(
                target.to_string(),
                port,
                service, 
                username.clone(), 
                password.clone(), 
                proxy_config.clone(),
                username_suffix.clone(),
                retries,timeout,single_account
            ).await;

            match result {
                Ok(res) => {
                    // println!("Brute force successful for service: {}", service);
                    
                 results.extend(res);
                }
                Err(e) => {
                    // println!("Error during brute force for service {}: {:?}", service, e);
                    err_msg.push(e.to_string());
                    app_handle.emit("brute_force_error", e.to_string()).unwrap_or_default();
                }
            }   
        }
    }



    Ok(results) // 直接返回结果
}



#[tauri::command]
fn stop_brute_force() -> Result<String, String> {
    // 设置运行状态为false，停止爆破任务
    unsafe {
        BRUTE_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
    };
    Ok(("爆破任务已停止").to_string())
}




// #[cfg(test)]
// mod tests {
//     use serde_json::json;

//     use super::*;
//     #[tokio::test]
//     async fn start_brute_force_test() {

//         let proxy_details = ProxyDetails {
//             enabled: false,
//             host: String::from("127.0.0.1"),
//             password: Option::None,
//             port: String::from("7897"),
//             username: Option::None,
//         };
    
//         // 使用 ProxyDetails 实例创建一个 ProxyConfig 实例
//         let proxy_config = ProxyConfig {
//             socks5: proxy_details,
//         };

//         let target = "127.0.0.1:22".to_string();
//         let single_account = true;
//         let username = "admin".to_string();
//         let password = "admin".to_string();
//         let threads = 10;
//         let timeout = 10;
//         let retries = 3;
//         let selected_services = vec!["SSH".to_string(),"FTP".to_string()];
//         let proxy_config = serde_json::to_value(proxy_config).unwrap();
//         let port_check = true;
//         let port_settings = HashMap::new();
//         let username_suffix = "".to_string();
//         let result = start_brute_force(target, single_account ,port_check,username, 
//             password,username_suffix, threads, timeout, retries, selected_services, proxy_config, port_settings).await;
//         println!("{:?}", result);
//     }
// }