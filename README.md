# DHRustHttp

一个用 Rust 编写的轻量级静态文件 HTTP 服务器，支持目录浏览、HTML/静态资源访问与文件下载，默认监听 8080 端口，如被占用会自动递增端口。

## 功能特性
- 静态文件服务：可直接访问当前目录下的任意文件
- 目录浏览：美观的目录列表，目录优先排序
- HTML 渲染：对 `.html` 文件以 `text/html` 正确返回
- 文件下载：自动推断 MIME 类型；支持 `inline`（预览）或 `attachment`（下载）模式
- 端口自动探测：默认从 `8080` 开始，若占用则递增查找可用端口
- 监听地址配置：支持指定监听 IP（如仅本机 `127.0.0.1` 或所有网卡 `0.0.0.0`）
- 自动首页：目录访问时优先返回 `index.html` 或 `index.htm`
- 大文件流式传输：支持 Range 请求（断点续传），适合大文件下载
- CORS 支持与访问日志

## 快速开始

### 开发模式运行（调试）
```powershell
# 在项目根目录
cargo run
```
启动后控制台会打印实际使用的端口，例如：
```
端口 8080 被占用，尝试下一个端口...
端口 8080 被占用，找到可用端口: 8081
端口 8080 被占用，使用端口 8081 代替
访问 http://localhost:8081 查看文件列表
```

### 发布打包（Release）
```powershell
cargo build --release
```
生成的可执行文件在：`target\release\DHRustHttp.exe`

### 运行已打包的可执行文件
```powershell
.\target\release\DHRustHttp.exe
```

### 访问
- 文件列表页：`http://localhost:<端口>/`
- 访问具体文件：`http://localhost:<端口>/<文件名>`（例如：`http://localhost:8080/test.html`）

## 先决条件
- Rust 工具链（stable）：https://www.rust-lang.org/tools/install
- 平台：Windows / Linux / macOS
- 文档默认使用 Windows PowerShell；Linux/macOS 将环境变量写法改为 bash，例如：
	```bash
	export DHRUSTHTTP_PORT=9000
	export DHRUSTHTTP_MAX_TRIES=200
	export DHRUSTHTTP_ROOT=/some/folder
	cargo run
	```

## 配置方式

支持命令行参数与环境变量两种方式（两者可混用，命令行优先于环境变量）：

### 命令行参数（开发模式）
```powershell
# 指定起始端口（默认 8080）
cargo run -- --port 9000

# 指定监听地址（默认 0.0.0.0，仅本机可用 127.0.0.1）
cargo run -- --host 127.0.0.1

# 指定最大尝试数量（默认 100，从起始端口起递增尝试）
cargo run -- --max-tries 50

# 指定服务器根目录（默认当前工作目录）
cargo run -- --root "F:\\SomeFolder"

# 指定文件返回模式（inline=预览，attachment=下载，默认 inline）
cargo run -- --disposition attachment

# 参数可组合使用
cargo run -- --host 127.0.0.1 --port 9000 --max-tries 10 --root . --disposition inline
```

### 命令行参数（运行已打包可执行文件）
```powershell
.\target\release\DHRustHttp.exe --host 127.0.0.1 --port 9000 --max-tries 50 --root . --disposition attachment
```

### 环境变量（PowerShell）
```powershell
$env:DHRUSTHTTP_HOST="127.0.0.1"
$env:DHRUSTHTTP_PORT=9000
$env:DHRUSTHTTP_MAX_TRIES=200
$env:DHRUSTHTTP_ROOT="F:\\SomeFolder"
$env:DHRUSTHTTP_DISPOSITION="attachment"

# 开发模式读取环境变量
cargo run

# 或运行已打包的可执行文件
.\target\release\DHRustHttp.exe
```

### 配置项一览
- `--host` 或 `DHRUSTHTTP_HOST`：监听地址（默认 `0.0.0.0`）
- `--port` 或 `DHRUSTHTTP_PORT`：起始端口（默认 `8080`）
- `--max-tries` 或 `DHRUSTHTTP_MAX_TRIES`：最大尝试数量（默认 `100`），从起始端口开始递增探测
- `--root` 或 `DHRUSTHTTP_ROOT`：服务器根目录（默认当前工作目录）
- `--disposition` 或 `DHRUSTHTTP_DISPOSITION`：文件返回模式，`inline`（预览）或 `attachment`（下载），默认 `inline`

## 目录结构
```
DHRustHttp/
├─ src/
│  └─ main.rs            # 服务主程序
├─ Cargo.toml            # 依赖清单
└─ README.md             # 使用文档（本文件）
```

## 查看帮助
```powershell
cargo run -- --help
# 或已打包版本
.\target\release\DHRustHttp.exe --help
```

## 安全提示
- 程序默认监听 `0.0.0.0:<端口>`，同一局域网设备可访问；如仅需本机访问，可使用 `--host 127.0.0.1` 限制监听地址。
- Windows 首次运行可能触发防火墙弹窗，请按需允许。

## 启用访问日志
- 本程序已集成 `env_logger`，可使用 `RUST_LOG` 控制日志级别：
	```powershell
	$env:RUST_LOG=info; cargo run
	# 或运行发布版
	$env:RUST_LOG=info; .\target\release\DHRustHttp.exe
	```

## 已知限制
- ~~大文件当前通过 `fs::read` 一次性读取到内存，暂不支持流式传输与 Range 请求（规划中）~~（已支持）
- 目录索引暂不支持搜索/分页（规划中）。
- MIME 基于扩展名推断，未知类型返回 `application/octet-stream`。

## 快速试运行
在项目根目录创建一个简单页面并访问：
```powershell
@'
<!doctype html><meta charset="utf-8"><title>OK</title><h1>It Works!</h1>
'@ | Out-File -Encoding utf8 test.html

# 创建一个 index.html 作为首页
@'
<!doctype html><meta charset="utf-8"><title>首页</title><h1>欢迎访问文件服务器</h1><a href="/test.html">查看测试页</a>
'@ | Out-File -Encoding utf8 index.html

cargo run
# 浏览器访问
# http://localhost:8080/         （显示 index.html）
# http://localhost:8080/test.html （显示测试页）
```

## 高级功能使用

### Range 请求（断点续传）
客户端可发送 Range 头进行分片下载：
```bash
# 获取文件前 1KB
curl -H "Range: bytes=0-1023" http://localhost:8080/largefile.zip

# 从 1MB 开始到文件末尾
curl -H "Range: bytes=1048576-" http://localhost:8080/largefile.zip

# 获取最后 4KB
curl -H "Range: bytes=-4096" http://localhost:8080/largefile.zip
```
服务器返回：
- `206 Partial Content`：成功的范围请求
- `416 Range Not Satisfiable`：无效范围
- `Accept-Ranges: bytes`：表明支持范围请求

### 强制下载模式
```powershell
# 设置为 attachment 模式，浏览器会下载而非预览
.\target\release\DHRustHttp.exe --disposition attachment
```

### 仅本机访问
```powershell
# 仅监听本机地址，局域网无法访问
.\target\release\DHRustHttp.exe --host 127.0.0.1
```

## 设计说明
- 使用 `warp` 作为 HTTP 框架，`tokio` 作为异步运行时
- 通过 `mime_guess` 根据扩展名推断 MIME 类型
- 目录列表页面服务端渲染，目录优先显示；访问目录时优先返回 `index.html` 或 `index.htm`
- 安全性：限制路径在根目录下，避免目录穿越
- 大文件支持：基于 `tokio_util::io::ReaderStream` 流式传输，支持 Range 请求（断点续传）

## Roadmap（未来计划）
- ~~可配置的 `Content-Disposition`（inline/attachment）~~（已支持）
- ~~支持 `--host` 指定监听地址~~（已支持）
- ~~自动索引首页（优先返回 `index.html`）~~（已支持）
- ~~断点续传与范围请求（Range Requests）~~（已支持）
- 目录列表分页与搜索
- 基于前端的更丰富文件浏览 UI（缩略图预览、排序切换等）
- 带宽限速与并发连接数限制
- 访问控制（基础认证/白名单）
- 访问日志格式自定义与文件落盘## 常见问题
- 端口占用：程序会自动尝试下一个端口；也可通过 `--port` 或 `DHRUSTHTTP_PORT` 指定起始端口
- 权限问题（Windows）：如遇 `os error 10013`，尝试以管理员权限运行，或更换端口

## 许可证
MIT
