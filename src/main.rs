use std::path::Path;
use std::fs;
use warp::{Filter, Reply, reject::Rejection};
use mime_guess;

#[tokio::main]
async fn main() {
    println!("启动 HTTP 服务器在端口 8888...");
    
    // 获取当前工作目录
    let current_dir = std::env::current_dir()
        .expect("无法获取当前目录");
    
    println!("服务器根目录: {}", current_dir.display());
    
    // 创建静态文件服务路由
    let files = warp::path::tail()
        .and(warp::get())
        .and_then(serve_file);
    
    // 根路径路由 - 显示目录列表
    let root = warp::path::end()
        .and(warp::get())
        .and_then(serve_directory);
    
    // 组合所有路由
    let routes = root.or(files)
        .with(warp::cors().allow_any_origin())
        .with(warp::log("http_server"));
    
    println!("HTTP 服务器已启动！");
    println!("访问 http://localhost:8888 查看文件列表");
    println!("按 Ctrl+C 停止服务器");
    
    warp::serve(routes)
        .run(([0, 0, 0, 0], 8888))
        .await;
}

// 处理文件请求
async fn serve_file(tail: warp::path::Tail) -> Result<Box<dyn Reply>, Rejection> {
    let file_path = tail.as_str();
    let current_dir = std::env::current_dir().unwrap();
    let full_path = current_dir.join(file_path);
    
    // 安全检查：确保请求的文件在当前目录内
    if !full_path.starts_with(&current_dir) {
        return Err(warp::reject::not_found());
    }
    
    if full_path.is_file() {
        match fs::read(&full_path) {
            Ok(contents) => {
                // 根据文件扩展名猜测 MIME 类型
                let mime_type = mime_guess::from_path(&full_path)
                    .first_or_octet_stream()
                    .to_string();
                
                let response = warp::http::Response::builder()
                    .header("content-type", mime_type)
                    .header("content-disposition", format!("inline; filename=\"{}\"", 
                        full_path.file_name().unwrap().to_string_lossy()))
                    .body(contents)
                    .unwrap();
                
                Ok(Box::new(response))
            }
            Err(_) => Err(warp::reject::not_found()),
        }
    } else if full_path.is_dir() {
        // 如果是目录，显示目录内容
        let dir_content = serve_directory_content_internal(&full_path)?;
        Ok(Box::new(warp::reply::html(dir_content)))
    } else {
        Err(warp::reject::not_found())
    }
}

// 处理根目录请求
async fn serve_directory() -> Result<Box<dyn Reply>, Rejection> {
    let current_dir = std::env::current_dir().unwrap();
    let dir_content = serve_directory_content_internal(&current_dir)?;
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
