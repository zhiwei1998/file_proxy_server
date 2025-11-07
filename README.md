# File Proxy Server

一个功能强大的文件代理服务器，支持HTTP/HTTPS请求转发、SOCKS5代理中转以及Alist文件系统集成，适用于文件下载、代理访问等场景。

## 功能特点

### 🚀 核心功能
- **HTTP/HTTPS代理转发**：接收客户端请求并转发到目标URL
- **SOCKS5代理支持**：可配置SOCKS5代理服务器进行请求中转，支持认证
- **Alist文件系统集成**：支持Alist签名URL验证和文件链接获取
- **大文件传输**：支持传输超大文件（最大约999GB）
- **灵活的配置系统**：支持命令行参数和YAML配置文件
- **302重定向处理**：服务器端自动追踪和处理所有重定向跳转，支持自定义拦截

### 🔒 安全特性
- **HMAC-SHA256签名验证**：实现Alist链接签名验证机制
- **自定义DNS配置**：支持配置自定义DNS服务器
- **连接超时控制**：可配置代理超时时间和重定向专用超时
- **URL拦截功能**：支持基于关键词的重定向URL拦截机制

### 📝 其他特性
- **多级日志系统**：支持debug、info、warn、error四种日志级别
- **Docker容器化**：提供完整的Docker支持和自动化部署配置
- **健康检查**：容器内置健康检查机制
- **智能重试机制**：针对网络错误自动重试，提高请求成功率
- **URL缓存系统**：可缓存重定向结果，提高重复请求的响应速度

## 安装部署

### 方法一：Docker部署（推荐）

```bash
# 拉取镜像并运行容器（假设已构建镜像）
docker run -d \
  --name file-proxy-server \
  -p 8001:8001 \
  -v ./config.yaml:/app/config.yaml \
  file-proxy-server:latest

# 或者直接使用docker-compose
docker-compose up -d
```

### 方法二：编译安装

```bash
# 克隆项目
git clone <项目仓库地址>
cd file_proxy_server

# 构建项目
go mod tidy
go build -ldflags="-w -s" -o file-proxy-server

# 运行服务
./file-proxy-server --config config.yaml
```

## 配置说明

### 配置文件（config.yaml）

配置文件示例：

```yaml
# 服务器配置
host: "0.0.0.0"
port: 8001

# SOCKS5代理配置
socks_host: "127.0.0.1"
socks_port: 1080
socks_username: "username"
socks_password: "password"

# 日志配置
log_level: "info"  # debug|info|warn|error

# Alist配置
alist_api_url: "http://10.10.2.140:5244"
alist_token: "alist-xxxxxxxxxxxxxxxxxxxxxxx"

# 网络配置
test_url: "https://www.baidu.com"
default_dns: "223.5.5.5:53"
proxy_timeout_seconds: 600

# 功能配置
enable_redirect: true  # 是否启用302跳转，true表示启用，false表示禁用
enable_cache: 5  # 缓存配置，0表示禁用，其他数字表示缓存分钟数
intercept_keyword: "app-free-download|download-cdn"  # 重定向拦截关键词，支持多个关键词以|分隔，为空时关闭拦截功能
```

### 命令行参数

```
用法:
  file-proxy-server [参数]

参数:
  --host string         监听主机 (默认 "0.0.0.0")
  --port int            监听端口 (默认 8001)
  --socks-host string   SOCKS5代理地址
  --socks-port int      SOCKS5代理端口
  --socks-username string SOCKS5代理用户名
  --socks-password string SOCKS5代理密码
  --log-level string    日志级别 (debug|info|warn|error, 默认 "info")
  --config string       配置文件路径
  --config-generate     生成配置文件并退出
  --help, -h            显示帮助信息
```

## 使用示例

### 1. 基本代理转发

直接通过URL路径传递目标地址：

```
http://your-server:8001/https://example.com/file.zip
```

### 2. 使用URL参数

通过查询参数指定目标URL和路径：

```
http://your-server:8001/?url=https://example.com&path=file.zip
```

### 3. Alist文件代理

处理Alist签名URL：

```
http://your-server:8001/path/to/file?sign=signature:expire
```

### 4. 生成配置文件

```bash
# 生成默认配置文件
./file-proxy-server --config-generate --config my-config.yaml
```

## 项目结构

```
file_proxy_server/
├── main.go           # 主程序代码
├── Dockerfile        # Docker构建配置
├── docker-entrypoint.sh  # Docker启动脚本
├── build.sh          # 构建脚本
├── go.mod            # Go模块定义
├── go.sum            # 依赖版本锁定
└── README.md         # 项目说明文档
```

## 技术栈

- **开发语言**：Go 1.23+
- **主要依赖**：
  - github.com/gorilla/mux: 路由处理
  - golang.org/x/net/proxy: SOCKS5代理支持
  - gopkg.in/yaml.v3: YAML配置文件解析
- **容器化**：Docker + Alpine Linux

## 环境变量（Docker）

- `PORT`：服务监听端口（默认8001）

## 注意事项

1. 请确保配置文件中的Alist API地址和Token正确设置
2. 使用SOCKS5代理时，确保代理服务器可访问且凭据正确
3. 大文件传输可能会占用较多系统资源，请根据实际情况调整配置
4. 生产环境建议配置适当的防火墙规则限制访问
5. 重定向拦截关键词支持多个，使用竖线(\|)分隔，匹配任意一个关键词即会拦截重定向
6. 重定向操作有独立的10秒超时设置，不受全局代理超时控制
7. 系统会自动重试网络错误（包括超时和EOF错误），最多重试3次，采用指数退避策略

## 故障排除

- **代理连接失败**：检查SOCKS5代理配置和网络连接
- **Alist链接验证失败**：确认Alist API地址和Token正确，以及签名是否过期
- **文件下载中断**：可能是网络问题或代理超时设置过小，尝试调整`proxy_timeout_seconds`参数
- **容器启动失败**：检查挂载的配置文件权限是否正确
- **重定向拦截不生效**：确认`intercept_keyword`配置是否正确，并检查日志级别是否为`debug`以查看详细匹配过程
- **网络错误频繁**：系统已内置重试机制，如需调整重试逻辑请修改代码中的`maxRetries`和等待时间设置

## 许可证

[MIT License](LICENSE)
