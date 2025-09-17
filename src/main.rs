use std::path::{Path, PathBuf};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use warp::{Filter, Reply, reject::Rejection};
use warp::http::{Response, StatusCode, header};
use warp::hyper::Body;
use mime_guess;
use clap::{Parser, ValueEnum};
use tokio::fs as tokio_fs;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

// Windows防火墙管理功能
#[cfg(windows)]
mod firewall {
    use std::process::Command;

    const RULE_NAME_PREFIX: &str = "DHRustHttp-Port-";

    // 检查指定端口的防火墙规则是否存在
    pub fn check_firewall_rule_exists(port: u16) -> bool {
        let rule_name = format!("{}{}", RULE_NAME_PREFIX, port);
        
        let output = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "show", "rule", 
                &format!("name={}", rule_name)
            ])
            .output();

        match output {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                // 如果输出包含规则名称，说明规则存在
                stdout.contains(&rule_name)
            }
            Err(_) => false,
        }
    }

    // 添加防火墙规则
    pub fn add_firewall_rule(port: u16) -> Result<(), String> {
        let rule_name = format!("{}{}", RULE_NAME_PREFIX, port);
        
        println!("正在为端口 {} 添加防火墙规则...", port);
        
        let output = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={}", port),
                "description=DHRustHttp HTTP Server Port"
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    println!("成功添加防火墙规则: {}", rule_name);
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    Err(format!("添加防火墙规则失败: {}", stderr))
                }
            }
            Err(e) => Err(format!("执行netsh命令失败: {}", e)),
        }
    }

    // 检查并确保端口通过防火墙
    pub fn ensure_port_allowed(port: u16) -> Result<(), String> {
        if check_firewall_rule_exists(port) {
            println!("端口 {} 的防火墙规则已存在", port);
            Ok(())
        } else {
            add_firewall_rule(port)
        }
    }
}

// 非Windows平台的空实现
#[cfg(not(windows))]
mod firewall {
    pub fn ensure_port_allowed(_port: u16) -> Result<(), String> {
        // 非Windows平台不需要防火墙检查
        Ok(())
    }
}

// 查找可用端口，从默认端口开始递增，并确保防火墙允许
fn find_available_port(host: IpAddr, start_port: u16, max_tries: u16, skip_firewall: bool) -> Result<u16, String> {
    println!("正在检查端口可用性...");

    let end = start_port.saturating_add(max_tries);
    for port in start_port..=end { // 最多尝试 max_tries+1 个端口
        match std::net::TcpListener::bind((host, port)) {
            Ok(_) => {
                if port != start_port {
                    println!("端口 {} 被占用，找到可用端口: {}", start_port, port);
                } else {
                    println!("端口 {} 可用", port);
                }
                
                // 检查并确保防火墙允许此端口（如果未跳过）
                if !skip_firewall {
                    match firewall::ensure_port_allowed(port) {
                        Ok(_) => {
                            println!("端口 {} 防火墙检查通过", port);
                            return Ok(port);
                        }
                        Err(e) => {
                            println!("端口 {} 防火墙配置失败: {}", port, e);
                            println!("注意: 可能需要管理员权限来修改防火墙设置");
                            println!("提示: 使用 --skip-firewall 参数跳过防火墙检查");
                            // 继续使用这个端口，但给用户警告
                            return Ok(port);
                        }
                    }
                } else {
                    println!("已跳过端口 {} 的防火墙检查", port);
                    return Ok(port);
                }
            }
            Err(_) => {
                println!("端口 {} 被占用，尝试下一个端口...", port);
            }
        }
    }
    Err(format!("无法在 [{}..={}] 范围内找到可用端口", start_port, end))
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum DispositionMode {
    Inline,
    Attachment,
}

#[derive(Clone, Debug)]
struct AppConfig {
    root: PathBuf,
    disposition: DispositionMode,
}

#[derive(Parser, Debug)]
#[command(name = "DHRustHttp", version, about = "一个简单的静态文件 HTTP 服务器", author = "PeiKeSmart")]
struct Cli {
    /// 起始端口（默认 8080）
    #[arg(short = 'p', long = "port", env = "DHRUSTHTTP_PORT", default_value_t = 8080)]
    port: u16,

    /// 最大尝试数量（从起始端口开始递增），默认 100
    #[arg(long = "max-tries", env = "DHRUSTHTTP_MAX_TRIES", default_value_t = 100)]
    max_tries: u16,

    /// 服务器根目录（默认当前工作目录）
    #[arg(long = "root", env = "DHRUSTHTTP_ROOT")]
    root: Option<String>,

    /// 监听地址（默认 0.0.0.0）仅支持 IP
    #[arg(long = "host", env = "DHRUSTHTTP_HOST", default_value = "0.0.0.0")]
    host: String,

    /// Content-Disposition 策略（inline/attachment），默认 inline
    #[arg(long = "disposition", env = "DHRUSTHTTP_DISPOSITION", value_enum, default_value_t = DispositionMode::Inline)]
    disposition: DispositionMode,

    /// 跳过防火墙检查和配置
    #[arg(long = "skip-firewall", env = "DHRUSTHTTP_SKIP_FIREWALL")]
    skip_firewall: bool,
    /// 禁用自动管理员自提升
    #[arg(long = "no-elevate", env = "DHRUSTHTTP_NO_ELEVATE")]
    no_elevate: bool,
    /// 启动后自动打开浏览器
    #[arg(long = "open-browser", env = "DHRUSTHTTP_OPEN_BROWSER")]
    open_browser: bool,
    /// (内部使用) 标记已提升
    #[arg(long = "__elevated", hide = true, default_value_t = false)]
    __elevated: bool,
    /// (内部使用) 原始工作目录
    #[arg(long = "__orig_cwd", hide = true)]
    __orig_cwd: Option<String>,
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("rundll32.exe")
            .arg("url.dll,FileProtocolHandler")
            .arg(url)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    #[cfg(windows)]
    {
        use crate::elevation;
        if !cli.no_elevate && !cli.__elevated {
            let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let cwd_str = cwd.to_string_lossy().to_string();
            let args: Vec<String> = std::env::args().skip(1).collect();
            if !elevation::is_elevated() {
                println!("(未提升) 尝试以管理员权限重新启动。可以使用 --no-elevate 禁用此行为。");
                match elevation::relaunch_as_admin(&args, &cwd_str) {
                    Ok(_) => { return; }
                    Err(e) => eprintln!("自提升失败: {}\n继续以当前权限运行", e),
                }
            }
        }
        if cli.__elevated {
            if let Some(orig) = &cli.__orig_cwd {
                if let Err(e) = std::env::set_current_dir(orig) {
                    eprintln!("恢复原工作目录失败: {}", e);
                } else {
                    println!("已恢复原工作目录: {}", orig);
                }
            }
        }
    }

    let default_port = cli.port;
    let max_tries = cli.max_tries;

    let host_ip: IpAddr = match cli.host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("host 参数必须是 IP 地址，例如 0.0.0.0 或 127.0.0.1");
            std::process::exit(2);
        }
    };

    let available_port = match find_available_port(host_ip, default_port, max_tries, cli.skip_firewall) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("查找可用端口失败: {}", e);
            std::process::exit(1);
        }
    };

    if available_port != default_port {
        println!("端口 {} 被占用，使用端口 {} 代替", default_port, available_port);
    }

    println!("启动 HTTP 服务器在端口 {}...", available_port);
    
    // 获取服务器根目录
    let current_dir = if let Some(root) = cli.root {
        std::path::PathBuf::from(root)
    } else {
        std::env::current_dir().expect("无法获取当前目录")
    };

    // 规范化根目录，但去掉Windows的UNC路径前缀
    let root_abs = current_dir.canonicalize().unwrap_or(current_dir);
    let display_path = if cfg!(windows) {
        // 在Windows上去掉 \\?\ 前缀，使路径更易读
        root_abs.to_string_lossy().strip_prefix(r"\\?\").unwrap_or(&root_abs.to_string_lossy()).to_string()
    } else {
        root_abs.display().to_string()
    };
    println!("服务器根目录: {}", display_path);

    let config = AppConfig { root: root_abs, disposition: cli.disposition };
    let cfg_filter = warp::any().map(move || config.clone());
    
    // 创建静态文件服务路由
    let files = warp::path::tail()
        .and(warp::get())
        .and(cfg_filter.clone())
        .and(warp::header::optional::<String>("range"))
        .and_then(serve_file);
    
    // 根路径路由 - 显示目录列表
    let root = warp::path::end()
        .and(warp::get())
        .and(cfg_filter.clone())
        .and_then(serve_directory);
    
    // 组合所有路由（shutdown 路由稍后加入，因为需要 tx_cell）
    let base_routes = root.or(files)
        .with(warp::cors().allow_any_origin())
        .with(warp::log("http_server"));
    
    println!("HTTP 服务器已启动！");
    println!("访问 http://{}:{} 或 http://localhost:{} 查看文件列表", host_ip, available_port, available_port);
    println!("按 Ctrl+C 停止服务器，输入 q 回车优雅退出，或访问 http://localhost:{}/__shutdown", available_port);

    if cli.open_browser {
        let url = format!("http://localhost:{}", available_port);
        println!("正在打开浏览器: {} (可用 --open-browser 控制)", url);
        open_browser(&url);
    }

    let addr = SocketAddr::from((host_ip, available_port));

    use std::sync::{Arc, atomic::{AtomicBool, Ordering}, Mutex};
    use tokio::sync::oneshot;
    let shutting_down = Arc::new(AtomicBool::new(false));
    let shutdown_done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = oneshot::channel::<()>();
    let tx_cell = Arc::new(Mutex::new(Some(tx)));
    {
        let shutting_down = shutting_down.clone();
        let tx_cell = tx_cell.clone();
        let shutdown_done = shutdown_done.clone();
        ctrlc::set_handler(move || {
            if !shutting_down.swap(true, Ordering::SeqCst) {
                println!("\n收到 Ctrl+C，正在优雅关闭...");
                if let Some(sender) = tx_cell.lock().ok().and_then(|mut g| g.take()) {
                    let _ = sender.send(());
                }
                // 等待优雅关闭完成（最多 5 秒），然后以 0 退出
                let start = std::time::Instant::now();
                while !shutdown_done.load(Ordering::SeqCst) && start.elapsed() < std::time::Duration::from_secs(5) {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                std::process::exit(0);
            }
        }).expect("无法注册 Ctrl+C 处理程序");
    }

    // 增加 HTTP 本地关闭路由 /__shutdown
    let tx_filter = {
        let tx_cell = tx_cell.clone();
        warp::any().map(move || tx_cell.clone())
    };
    let shutdown_route = warp::path("__shutdown")
        .and(warp::get())
        .and(warp::addr::remote())
        .and(tx_filter)
        .and_then(shutdown_handler);
    let routes = base_routes.or(shutdown_route);

    let (addr_bound, server_fut) = warp::serve(routes).bind_with_graceful_shutdown(addr, async {
        let _ = rx.await; // 等待信号
    });
    println!("监听地址: {}", addr_bound);

    server_fut.await;
    println!("服务器已优雅关闭");
    shutdown_done.store(true, Ordering::SeqCst);
    return; // 正常结束
}

// 处理文件请求
async fn serve_file(tail: warp::path::Tail, cfg: AppConfig, range_header: Option<String>) -> Result<Box<dyn Reply>, Rejection> {
    let file_path = tail.as_str().to_string();
    serve_file_by_path(file_path, cfg, range_header).await
}

async fn serve_file_by_path(file_path: String, cfg: AppConfig, range_header: Option<String>) -> Result<Box<dyn Reply>, Rejection> {
    let root = cfg.root.clone();
    let root_abs = root.clone();
    let mut full_path = root_abs.join(&file_path);
    // 规范化
    full_path = full_path.canonicalize().unwrap_or(full_path);

    // 安全检查：确保请求的文件在根目录内
    if !full_path.starts_with(&root_abs) {
        return Err(warp::reject::not_found());
    }

    // 若为目录，尝试 index.html/htm
    if full_path.is_dir() {
        let idx_html = full_path.join("index.html");
        let idx_htm = full_path.join("index.htm");
        if idx_html.is_file() {
            full_path = idx_html;
        } else if idx_htm.is_file() {
            full_path = idx_htm;
        } else {
            // 否则显示目录列表
            let dir_content = serve_directory_content_internal(&full_path)?;
            return Ok(Box::new(warp::reply::html(dir_content)));
        }
    }

    if full_path.is_file() {
        // 根据文件扩展名猜测 MIME 类型
        let mime_type = mime_guess::from_path(&full_path)
            .first_or_octet_stream()
            .to_string();

        let cd_mode = match cfg.disposition { DispositionMode::Inline => "inline", DispositionMode::Attachment => "attachment" };
        let filename = full_path.file_name().unwrap().to_string_lossy().to_string();

        // 获取文件大小
        let meta = match tokio_fs::metadata(&full_path).await { Ok(m) => m, Err(_) => return Err(warp::reject::not_found()) };
        let file_len = meta.len();

        // Range 处理
        if let Some(range_val) = range_header {
            if let Some((start, end)) = parse_range(&range_val, file_len) {
                use tokio::io::AsyncSeekExt;
                let mut file = match tokio_fs::File::open(&full_path).await { Ok(f) => f, Err(_) => return Err(warp::reject::not_found()) };
                if AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(start)).await.is_err() {
                    return Err(warp::reject::not_found());
                }
                let to_read = end - start + 1;
                let limited = file.take(to_read);
                let stream = ReaderStream::new(limited);
                let body = Body::wrap_stream(stream);
                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::PARTIAL_CONTENT;
                let headers = response.headers_mut();
                headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_str(&mime_type).unwrap_or(header::HeaderValue::from_static("application/octet-stream")));
                headers.insert(header::CONTENT_DISPOSITION, header::HeaderValue::from_str(&format!("{}; filename=\"{}\"", cd_mode, filename)).unwrap());
                headers.insert(header::ACCEPT_RANGES, header::HeaderValue::from_static("bytes"));
                headers.insert(header::CONTENT_RANGE, header::HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, file_len)).unwrap());
                headers.insert(header::CONTENT_LENGTH, header::HeaderValue::from_str(&to_read.to_string()).unwrap());
                return Ok(Box::new(response));
            } else {
                // 416 Range Not Satisfiable
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                let headers = response.headers_mut();
                headers.insert(header::CONTENT_RANGE, header::HeaderValue::from_str(&format!("bytes */{}", file_len)).unwrap());
                return Ok(Box::new(response));
            }
        }

        // 正常 200 全量响应（流式）
        let file = match tokio_fs::File::open(&full_path).await { Ok(f) => f, Err(_) => return Err(warp::reject::not_found()) };
        let stream = ReaderStream::new(file);
        let body = Body::wrap_stream(stream);
        let mut response = Response::new(body);
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_str(&mime_type).unwrap_or(header::HeaderValue::from_static("application/octet-stream")));
        headers.insert(header::CONTENT_DISPOSITION, header::HeaderValue::from_str(&format!("{}; filename=\"{}\"", cd_mode, filename)).unwrap());
        headers.insert(header::ACCEPT_RANGES, header::HeaderValue::from_static("bytes"));
        return Ok(Box::new(response));
    } else {
        Err(warp::reject::not_found())
    }
}

// 处理根目录请求
async fn serve_directory(cfg: AppConfig) -> Result<Box<dyn Reply>, Rejection> {
    let dir_content = serve_directory_content_internal(&cfg.root)?;
    Ok(Box::new(warp::reply::html(dir_content)))
}

// 生成目录内容的 HTML 页面
fn serve_directory_content_internal(dir_path: &Path) -> Result<String, Rejection> {
    match fs::read_dir(dir_path) {
        Ok(entries) => {
            let mut html = String::from(r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>文件浏览器</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .file-list { list-style: none; padding: 0; }
        .file-item { 
            margin: 10px 0; 
            padding: 10px; 
            border: 1px solid #ddd; 
            border-radius: 5px;
            background: #f9f9f9;
        }
        .file-item:hover { background: #f0f0f0; }
        a { text-decoration: none; color: #0066cc; }
        a:hover { text-decoration: underline; }
        .file-icon { margin-right: 10px; }
        .directory { color: #ff6600; }
        .file { color: #0066cc; }
    </style>
</head>
<body>
    <h1>📁 文件浏览器</h1>
    <p><strong>当前目录:</strong> "#);
            
            html.push_str(&dir_path.display().to_string());
            html.push_str("</p><ul class=\"file-list\">");
            
            let mut items: Vec<_> = entries.collect::<Result<Vec<_>, _>>()
                .map_err(|_| warp::reject::not_found())?;
            
            // 排序：目录在前，文件在后
            items.sort_by(|a, b| {
                let a_is_dir = a.path().is_dir();
                let b_is_dir = b.path().is_dir();
                
                match (a_is_dir, b_is_dir) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a.file_name().cmp(&b.file_name()),
                }
            });
            
            for entry in items {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();
                let path = entry.path();
                
                if path.is_dir() {
                    html.push_str(&format!(
                        r#"<li class="file-item"><span class="file-icon">📁</span><a href="{}" class="directory">{}/</a></li>"#,
                        file_name_str, file_name_str
                    ));
                } else {
                    html.push_str(&format!(
                        r#"<li class="file-item"><span class="file-icon">📄</span><a href="{}" class="file">{}</a></li>"#,
                        file_name_str, file_name_str
                    ));
                }
            }
            
            html.push_str("</ul></body></html>");
            
            Ok(html)
        }
        Err(_) => Err(warp::reject::not_found()),
    }
}

// 解析 Range 头，仅支持单段：bytes=start-end | bytes=start- | bytes=-suffix
fn parse_range(range: &str, file_len: u64) -> Option<(u64, u64)> {
    // 形如："bytes=..."
    let s = range.trim();
    let s = s.strip_prefix("bytes=")?;
    if let Some((start_s, end_s)) = s.split_once('-') {
        if !start_s.is_empty() {
            // start-[end?]
            let start: u64 = start_s.parse().ok()?;
            let end: u64 = if !end_s.is_empty() { end_s.parse().ok()? } else { file_len.saturating_sub(1) };
            if start > end || end >= file_len { return None; }
            Some((start, end))
        } else {
            // -suffix
            let suffix: u64 = end_s.parse().ok()?;
            if suffix == 0 { return None; }
            let start = file_len.saturating_sub(suffix);
            let end = file_len.saturating_sub(1);
            Some((start, end))
        }
    } else {
        None
    }
}

#[cfg(windows)]
mod elevation {
    use windows_sys::Win32::Foundation::{HANDLE, CloseHandle};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // 检测当前进程是否已提升(管理员)
    pub fn is_elevated() -> bool {
        unsafe {
            let process = GetCurrentProcess();
            let mut token: HANDLE = 0;
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 { return false; }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut ret_len: u32 = 0;
            let res = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len
            );
            CloseHandle(token);
            if res == 0 { return false; }
            elevation.TokenIsElevated != 0
        }
    }

    // 以管理员权限重新启动 (调用 powershell Start-Process -Verb RunAs)
    pub fn relaunch_as_admin(args: &[String], cwd: &str) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        // 重建参数并附加内部标记
        let mut rebuilt: Vec<String> = Vec::new();
        rebuilt.push("--__elevated".to_string());
        rebuilt.push(format!("--__orig_cwd={}", cwd));
        for a in args {
            if a.starts_with("--__elevated") || a.starts_with("--__orig_cwd=") { continue; }
            rebuilt.push(a.clone());
        }
        // 在 PowerShell 中执行: Start-Process <exe> -Verb RunAs -WorkingDirectory <cwd> -ArgumentList 'arg1','arg2'
        let arg_list = rebuilt.iter().map(|s| format!("'{}'", s.replace("'", "''"))).collect::<Vec<_>>().join(",");
        let ps_cmd = format!(
            "Start-Process -FilePath '{}' -Verb RunAs -WorkingDirectory '{}' -ArgumentList {}",
            exe.display(), cwd.replace("'", "''"), arg_list
        );
        let status = std::process::Command::new("powershell")
            .arg("-NoProfile").arg("-Command").arg(ps_cmd)
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() { return Err(format!("提升进程启动失败, 状态: {:?}", status)); }
        Ok(())
    }
}

#[cfg(not(windows))]
mod elevation {
    pub fn is_elevated() -> bool { true }
    pub fn relaunch_as_admin(_args: &[String], _cwd: &str) -> Result<(), String> { Ok(()) }
}

async fn shutdown_handler(remote: Option<SocketAddr>, tx_cell: std::sync::Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>) -> Result<impl Reply, Rejection> {
    // 仅允许来自本机的请求触发关闭
    if let Some(addr) = remote {
        if !(addr.ip().is_loopback() || addr.ip().is_unspecified()) {
            return Ok(warp::reply::with_status("forbidden", StatusCode::FORBIDDEN));
        }
    }
    if let Some(sender) = tx_cell.lock().ok().and_then(|mut g| g.take()) {
        let _ = sender.send(());
        Ok(warp::reply::with_status("shutting down", StatusCode::OK))
    } else {
        Ok(warp::reply::with_status("already shutting down", StatusCode::OK))
    }
}
