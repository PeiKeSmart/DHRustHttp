# DHRustHttp

一个简单的静态文件 HTTP 服务器，支持：

- 自动/递增端口检测
- Windows 防火墙规则自动添加（可跳过）
- 自动管理员权限自提升（可禁用）
- 目录列表 + 文件 Range 请求
- Content-Disposition inline/attachment 切换
- 优雅退出 (Ctrl+C)
- 可选启动后自动打开浏览器

## 安装与构建
```bash
cargo build --release
```

## 命令行参数
| 参数 | 说明 | 默认 |
|------|------|------|
| `--port -p` | 起始端口 | 8080 |
| `--max-tries` | 端口递增最大尝试次数 | 100 |
| `--root` | 指定服务器根目录 | 当前工作目录 |
| `--host` | 监听地址(仅IP) | 0.0.0.0 |
| `--disposition` | inline 或 attachment | inline |
| `--skip-firewall` | 跳过防火墙检测与添加 | 关闭 |
| `--no-elevate` | 禁用自动管理员自提升 | 关闭 |
| `--open-browser` | 启动后自动打开浏览器 | 关闭 |

内部参数（不需手动使用）：`--__elevated` / `--__orig_cwd`

## 典型用法
```bash
# 普通启动（若非管理员会尝试提升）
DHRustHttp.exe

# 禁用自动提升
DHRustHttp.exe --no-elevate

# 跳过防火墙添加（适合已配置或无权限环境）
DHRustHttp.exe --skip-firewall

# 启动并自动打开浏览器
DHRustHttp.exe --open-browser

# 指定根目录与端口
DHRustHttp.exe --root C:\\data --port 9000
```

## Windows 防火墙
- 首次需要管理员权限以添加规则（命名格式：`DHRustHttp-Port-<端口>`）。
- 若无权限会继续运行但提示可使用 `--skip-firewall`。

## 自提升逻辑
- 未提升且未指定 `--no-elevate` 时，会重新以管理员身份启动。
- 原工作目录通过隐藏参数传递并恢复，保证相对路径一致性。

## 浏览器自动打开
使用 `--open-browser` 在成功启动后自动打开 `http://localhost:<端口>`。

## 退出
Ctrl+C 触发优雅关闭。

## License
MIT
