# 构建阶段 - 使用官方Go镜像
FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .
RUN sed -i 's#https\?://dl-cdn.alpinelinux.org/alpine#https://mirrors.tuna.tsinghua.edu.cn/alpine#g' /etc/apk/repositories && \
    apk add --no-cache git && \
    go mod download && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o file-proxy-server

# 运行时阶段 - 使用最小化的Alpine镜像
FROM alpine:3.18

WORKDIR /app

RUN sed -i 's#https\?://dl-cdn.alpinelinux.org/alpine#https://mirrors.tuna.tsinghua.edu.cn/alpine#g' /etc/apk/repositories && \
    apk add --no-cache ca-certificates tzdata bash tini && \
    mkdir -p /app


# 从构建阶段复制文件
COPY --from=builder /app/file-proxy-server /usr/local/bin/
COPY docker-entrypoint.sh /usr/local/bin/


RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/file-proxy-server 



# 设置数据卷（用于挂载自定义配置）
VOLUME ["/app"]

# 设置健康检查
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --quiet --tries=1 --spider http://localhost:${PORT:-8001}/ || exit 1


# 使用tini作为入口点
ENTRYPOINT ["/sbin/tini", "--", "docker-entrypoint.sh"]

CMD ["file-proxy-server", "--config", "/app/config.yaml"]
EXPOSE 8001
