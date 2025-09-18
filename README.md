# DHRustHttp

一个简单的静态文件 HTTP 服务器，支持：

- 自动/递增端口检测
- Windows 防火墙规则自动添加（可跳过）
- **智能提权模式**：默认懒提权（无窗口切换），可选传统提权
- 目录列表 + 文件 Range 请求
- Content-Disposition inline/attachment 切换
- 优雅退出 (Ctrl+C)
- 可选启动后自动打开浏览器

## 安装与构建

### 标准构建
```bash
cargo build --release
```

### 优化构建（推荐）
项目已配置了优化的release配置，包括：
- LTO (Link Time Optimization) 链接时优化
- 最小化二进制大小优化 (`opt-level = "s"`)
- 移除调试信息和符号表
- panic处理优化

```bash
# 构建优化版本
cargo build --release

# 使用UPX进一步压缩（可选，需先安装UPX）
# 从 ~2.2MB 压缩到 ~700KB (压缩率 ~32%)
upx --best --lzma target/release/DHRustHttp.exe
```

### 自动化构建脚本
```bash
# Windows: 使用提供的批处理脚本
.\build_release.bat
```

## 性能优化说明
- **LTO**: 显著减小二进制大小，提高运行时性能
- **代码生成单元**: 设置为1个单元以获得最佳优化
- **剥离**: 移除所有调试符号和不必要的元数据
- **UPX压缩**: 可进一步将二进制大小减少至原来的32%

## 命令行参数
| 参数 | 说明 | 默认 |
|------|------|------|
| `--port -p` | 起始端口 | 8080 |
| `--max-tries` | 端口递增最大尝试次数 | 100 |
| `--root` | 指定服务器根目录 | 当前工作目录 |
| `--host` | 监听地址(仅IP) | 0.0.0.0 |
| `--disposition` | inline 或 attachment | inline |
| `--skip-firewall` | 跳过防火墙检测与添加 | 关闭 |
| `--eager-elevate` | 启动时整进程重启提权（传统模式） | 关闭 |
| `--no-elevate` | 禁用所有提权行为 | 关闭 |
| `--open-browser` | 启动后自动打开浏览器 | 关闭 |

内部参数（不需手动使用）：`--__elevated` / `--__orig_cwd`

## 提权模式说明

### 🚀 懒提权（默认推荐）
- **行为**：主进程立即启动，无窗口切换，仅在需要时后台以管理员执行特定操作
- **优势**：启动快速，用户体验丝滑，无空窗期
- **何时提权**：添加防火墙规则失败时，后台弹出 UAC 但不重启主进程
- **启用**：默认行为，无需参数

### ⚡ 传统提权
- **行为**：检测到非管理员时，整个进程重启为管理员权限
- **特点**：会切换到新的管理员窗口，有明显的等待时间
- **启用**：`--eager-elevate`

### 🚫 禁用提权
- **行为**：完全不尝试获取管理员权限
- **适用**：已手动配置防火墙规则，或不需要防火墙配置
- **启用**：`--no-elevate`

## 典型用法
```bash
# 🚀 快速启动（推荐，默认懒提权）
DHRustHttp.exe

# 🚀 启动并自动打开浏览器
DHRustHttp.exe --open-browser

# ⚡ 传统提权模式（会切换窗口）
DHRustHttp.exe --eager-elevate

# 🚫 禁用所有提权
DHRustHttp.exe --no-elevate

# 🚫 跳过防火墙添加（适合已配置或无权限环境）
DHRustHttp.exe --skip-firewall

# 📁 指定根目录与端口
DHRustHttp.exe --root C:\\data --port 9000

# 🌐 仅本地访问
DHRustHttp.exe --host 127.0.0.1
```

## Windows 防火墙自动配置
- **规则命名**：`DHRustHttp-Port-<端口号>`（如 `DHRustHttp-Port-8080`）
- **懒提权模式**：首次添加规则失败时，后台以管理员执行，不阻塞服务器启动
- **传统模式**：需要管理员权限时会重启整个程序
- **手动配置**：可提前手动添加规则避免后续提权需求：
  ```cmd
  netsh advfirewall firewall add rule name="DHRustHttp-Port-8080" dir=in action=allow protocol=TCP localport=8080
  ```

## 退出方式
- **Ctrl+C**：优雅关闭服务器
- **HTTP请求**：访问 `http://localhost:<端口>/__shutdown` 
- **命令行输入**：在终端输入 `q` 然后回车

## 性能与安全特性
- **内存安全**：Rust 语言保障
- **异步I/O**：基于 Tokio 的高性能异步处理
- **Range 请求**：支持断点续传和流媒体
- **路径安全**：防止目录遍历攻击
- **优雅关闭**：确保连接正确断开

## License
MIT
