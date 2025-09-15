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
use tokio::net::TcpStream;

#[cfg(target_os = "windows")]
mod win_integration {
    use is_elevated::is_elevated;
    use runas::Command as RunasCommand;
    use std::process::Command;

    pub fn ensure_admin_or_relaunch() {
        if is_elevated() {
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("无法获取当前可执行路径: {}", e);
                return;
            }
        };
        let exe_dir = exe.parent().map(|p| p.to_path_buf());
        // 若已经带有内部标记 _elevated，说明已尝试过提权，避免循环
        let mut args: Vec<String> = std::env::args().skip(1).collect();
        if args.iter().any(|a| a == "--_elevated") {
            // 无法提权（用户拒绝或被策略阻止），直接返回让程序以非管理员继续运行
            eprintln!("已检测到 _elevated 标记，跳过再次提权。");
            return;
        }
        // 追加内部标记，防止失败后再次无限尝试
        args.push("--_elevated".to_string());
        // 若设置了确认环境变量，则在控制台提示并等待回车
        if std::env::var("DHRUSTHTTP_CONFIRM_ELEVATE").ok().filter(|v| !v.is_empty()).is_some() {
            println!("检测到非管理员权限，准备申请管理员权限。\n按 Enter 继续，或按 Ctrl+C 取消...");
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s);
        }
        println!("检测到非管理员权限，正在申请管理员权限...");
        // 优先使用 PowerShell 异步提升启动，旧进程立即退出，避免窗口停留
        let exe_ps = exe.to_string_lossy().replace("'", "''");
        let wd_ps = exe_dir
            .as_ref()
            .map(|d| d.to_string_lossy().replace("'", "''"))
            .unwrap_or_else(|| "".to_string());
        let args_escaped: Vec<String> = args
            .iter()
            .map(|a| format!("'{}'", a.replace("'", "''")))
            .collect();
        let ps_cmd = if args_escaped.is_empty() {
            // 无参数时省略 -ArgumentList，避免 @() 触发参数验证错误
            if wd_ps.is_empty() {
                format!(
                    "Start-Process -Verb RunAs -FilePath '{}' -WindowStyle Normal",
                    exe_ps
                )
            } else {
                format!(
                    "Start-Process -Verb RunAs -FilePath '{}' -WorkingDirectory '{}' -WindowStyle Normal",
                    exe_ps, wd_ps
                )
            }
        } else {
            let args_ps = args_escaped.join(", ");
            if wd_ps.is_empty() {
                format!(
                    "Start-Process -Verb RunAs -FilePath '{}' -ArgumentList @({}) -WindowStyle Normal",
                    exe_ps, args_ps
                )
            } else {
                format!(
                    "Start-Process -Verb RunAs -FilePath '{}' -ArgumentList @({}) -WorkingDirectory '{}' -WindowStyle Normal",
                    exe_ps, args_ps, wd_ps
                )
            }
        };

        let ps_spawn = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps_cmd])
            .spawn();

        match ps_spawn {
            Ok(_child) => {
                println!("已以管理员权限启动新进程，当前进程将退出...");
                std::process::exit(0);
            }
            Err(ps_err) => {
                eprintln!("通过 PowerShell 提权启动失败，尝试备用方案：{}", ps_err);
                // 回退到同步方式（可能会等待新进程退出）；至少保证可用性
                match RunasCommand::new(exe).args(&args).gui(false).status() {
                    Ok(_status) => {
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("管理员权限申请失败: {}", e);
                    }
                }
            }
        }
    }

    // 判断指定显示名称的规则是否存在
    fn rule_name_exists(rule_name: &str) -> Result<bool, String> {
        let name_escaped = rule_name.replace("'", "''");
        let ps = format!(
            "$n='{}'; if (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue) {{ 'YES' }}",
            name_escaped
        );
        let out = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .output()
            .map_err(|e| format!("执行 PowerShell 查询失败: {}", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("PowerShell 查询非零退出: {}", stderr.trim()));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let exists = stdout.lines().any(|l| l.trim().eq_ignore_ascii_case("YES"));
        Ok(exists)
    }

    fn list_firewall_rules_for_port(port: u16) -> Result<Vec<String>, String> {
        // 兼容性更好的 PowerShell 查询：
        // 逐条规则获取其端口过滤器，再在其中筛选 Protocol=TCP 且 LocalPort 包含所需端口；最后 PS 端去重
        // 注意：不处理端口范围/Any，仅匹配明确包含该端口的规则（与之前语义一致）
        let ps = format!(
            "${{p}}={}; Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | ForEach-Object {{ $r=$_; try {{ $fs = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; foreach ($f in $fs) {{ if ($f.Protocol -eq 'TCP') {{ $lp = $f.LocalPort; if ($null -ne $lp) {{ $ps = $p.ToString(); if ($lp -is [int]) {{ if ($lp -eq $p) {{ $r.DisplayName; break }} }} elseif ($lp -is [string]) {{ if ($lp -eq $ps) {{ $r.DisplayName; break }} elseif ($lp -like '*,*') {{ if ((($lp -split ',') | ForEach-Object {{ $_.Trim() }}) -contains $ps) {{ $r.DisplayName; break }} }} }} elseif ($lp -is [object[]]) {{ $sarr = $lp | ForEach-Object {{ $_.ToString() }}; if ($sarr -contains $ps) {{ $r.DisplayName; break }} }} }} }} }} }} catch {{ }} }} | Sort-Object -Unique",
            port
        );
        let out = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .output()
            .map_err(|e| format!("执行 PowerShell 查询失败: {}", e))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("PowerShell 查询非零退出: {}", stderr.trim()));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        // 再次在 Rust 端做一次去重与排序，双保险且输出稳定
        let set: std::collections::BTreeSet<String> = stdout
            .lines()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Ok(set.into_iter().collect())
    }

    /// 公开查询接口：返回匹配端口的入站允许 TCP 规则名称列表
    pub fn query_firewall_rules_for_port(port: u16) -> Result<Vec<String>, String> {
        list_firewall_rules_for_port(port)
    }

    pub fn ensure_firewall_open(port: u16) {
        // 使用唯一规则名，避免冲突
        let rule_name = format!("DHRustHttp-{}", port);
        let name_arg = format!("name=\"{}\"", rule_name);
        let port_arg = format!("localport={}", port);

        // 放行前先查询是否已有规则放开该端口
        match list_firewall_rules_for_port(port) {
            Ok(names) if !names.is_empty() => {
                println!("检测到已有放行规则（入站 TCP 端口 {}）：{}", port, names.join(", "));
                return; // 已有放行，无需再添加
            }
            Ok(_) => {
                // 没有命中，继续尝试添加规则
            }
            Err(e) => {
                eprintln!("查询现有防火墙规则失败（可忽略）：{}", e);
            }
        }

        // 若存在同名规则，则不再尝试添加，避免重复
        match rule_name_exists(&rule_name) {
            Ok(true) => {
                println!("已存在同名防火墙规则：{}，跳过新增。", rule_name);
                return;
            }
            Ok(false) => { /* 继续添加 */ }
            Err(e) => {
                eprintln!("查询同名规则失败（可忽略）：{}", e);
            }
        }

        // 添加规则（若已存在会失败，但我们将忽略“已存在”的情况）
        let output = Command::new("netsh")
            .args([
                "advfirewall","firewall","add","rule",
                &name_arg,
                "dir=in","action=allow","protocol=TCP",
                &port_arg,
            ])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if out.status.success() {
                    println!("已放行 Windows 防火墙端口 {}（规则名：{}）", port, rule_name);
                    // 再次查询并打印当前命中的规则名称
                    match list_firewall_rules_for_port(port) {
                        Ok(names) if !names.is_empty() => {
                            println!("当前端口 {} 命中的放行规则：{}", port, names.join(", "));
                        }
                        Ok(_) => {
                            eprintln!("警告：添加规则后仍未查询到端口 {} 的放行规则，可能被策略覆盖/限制。", port);
                        }
                        Err(e) => eprintln!("查询规则失败：{}", e),
                    }
                } else {
                    // 若规则已存在，输出通常包含“已存在”或“exists”，此时视为成功
                    let combined = format!("{}\n{}", stdout, stderr).to_lowercase();
                    if combined.contains("exist") || combined.contains("已存在") {
                        println!("防火墙规则已存在：端口 {} 已放行（规则名：{} 或其他）", port, rule_name);
                        if let Ok(names) = list_firewall_rules_for_port(port) {
                            if !names.is_empty() {
                                println!("当前端口 {} 命中的放行规则：{}", port, names.join(", "));
                            }
                        }
                    } else {
                        eprintln!("放行防火墙端口失败（可忽略，若已手工放行）：{}", combined.trim());
                    }
                }
            }
            Err(e) => {
                eprintln!("执行 netsh 失败：{}（可忽略，若已手工放行）", e);
                // 仍尝试报告当前命中的规则，帮助排查
                if let Ok(names) = list_firewall_rules_for_port(port) {
                    if !names.is_empty() {
                        println!("当前端口 {} 命中的放行规则：{}", port, names.join(", "));
                    }
                }
            }
        }
    }
}

// 查找可用端口，从默认端口开始递增
fn find_available_port(host: IpAddr, start_port: u16, max_tries: u16) -> Result<u16, String> {
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
                return Ok(port);
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

    ///（Windows）禁用自动添加防火墙规则
    #[arg(long = "no-firewall", env = "DHRUSTHTTP_NO_FIREWALL", default_value_t = false)]
    no_firewall: bool,

    /// 内部使用：标记已尝试提权重启，避免在无法提权环境中循环（隐藏参数）
    #[arg(long = "_elevated", hide = true, default_value_t = false)]
    _elevated: bool,
}

#[tokio::main]
async fn main() {
    // 初始化日志（支持 RUST_LOG）
    env_logger::init();

    let cli = Cli::parse();

    // Windows: 若非管理员则提权重启自身
    #[cfg(target_os = "windows")]
    {
        let elevated = is_elevated::is_elevated();
        println!("管理员模式: {}", if elevated { "是" } else { "否" });
        if !elevated {
            win_integration::ensure_admin_or_relaunch();
        }
    }

    let default_port = cli.port;
    let max_tries = cli.max_tries;

    // 打印当前工作目录与可执行文件路径，便于确认运行环境
    match std::env::current_dir() {
        Ok(cwd) => println!("当前工作目录: {}", cwd.display()),
        Err(e) => eprintln!("无法获取当前工作目录: {}", e),
    }
    match std::env::current_exe() {
        Ok(exe) => {
            println!("可执行文件路径: {}", exe.display());
            if let Some(dir) = exe.parent() {
                println!("可执行文件所在目录: {}", dir.display());
            }
        }
        Err(e) => eprintln!("无法获取可执行文件路径: {}", e),
    }

    let host_ip: IpAddr = match cli.host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("host 参数必须是 IP 地址，例如 0.0.0.0 或 127.0.0.1");
            std::process::exit(2);
        }
    };

    // 打印访问范围提示
    if host_ip.is_loopback() {
        println!("访问范围: 仅本机（loopback）");
    } else if host_ip.is_unspecified() {
        println!("访问范围: 所有网卡（0.0.0.0），同一局域网可访问；请确认防火墙已放行");
    } else {
        println!("访问范围: 仅网卡 IP {} 对应网段", host_ip);
    }

    let available_port = match find_available_port(host_ip, default_port, max_tries) {
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

    // 规范化根目录
    let root_abs = current_dir.canonicalize().unwrap_or(current_dir);
    println!("服务器根目录: {}", root_abs.display());

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
    
    // 组合所有路由
    let access_log = warp::log::custom(|info| {
        let method = info.method().to_string();
        let path = info.path().to_string();
        let status = info.status().as_u16();
        let elapsed_ms = info.elapsed().as_millis();
        let remote = info.remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".to_string());
        let referer = info.referer().unwrap_or("-");
        let ua = info.user_agent().unwrap_or("-");
        log::info!(
            target: "access",
            "remote={} method={} path={} status={} elapsed_ms={} referer={} user-agent={}",
            remote, method, path, status, elapsed_ms, referer, ua
        );
    });

    let routes = root.or(files)
        .with(warp::cors().allow_any_origin())
        .with(access_log);
    
    // Windows: 放行防火墙端口（若规则已存在将忽略）
    #[cfg(target_os = "windows")]
    {
        if cli.no_firewall {
            println!("已按参数 --no-firewall 跳过自动放行防火墙端口 {}", available_port);
        } else {
            win_integration::ensure_firewall_open(available_port);
        }
        // 汇总打印当前端口的防火墙状态
        match win_integration::query_firewall_rules_for_port(available_port) {
            Ok(names) if !names.is_empty() => println!("防火墙状态：端口 {} 已放行（规则：{}）", available_port, names.join(", ")),
            Ok(_) => println!("防火墙状态：未检测到端口 {} 的放行规则（可能仍可访问，取决于策略与其他规则）", available_port),
            Err(e) => println!("防火墙状态：查询失败（{}），请手动检查。", e),
        }
    }

    println!("HTTP 服务器已启动！");
    println!("访问 http://{}:{} 或 http://localhost:{} 查看文件列表", host_ip, available_port, available_port);
    println!("按 Ctrl+C 停止服务器");
    
    let addr = SocketAddr::from((host_ip, available_port));

    // 启动后异步进行一次端口开放自检（本机 TCP 连接）
    {
        let check_addr = addr;
        tokio::spawn(async move {
            // 略等片刻，让服务器完成绑定
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            match TcpStream::connect(check_addr).await {
                Ok(_) => println!("端口开放自检：本机到 {} 连接成功（端口已监听）", check_addr),
                Err(e) => eprintln!("端口开放自检：本机到 {} 连接失败：{}", check_addr, e),
            }
        });
    }
    warp::serve(routes)
        .run(addr)
        .await;
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
