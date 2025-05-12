#!/bin/bash
set -e

echo "=== 启动初始化 ==="

# 如果配置目录为空，则复制默认配置
if [ ! -f "/app/config.yaml" ]; then
  echo "未检测到配置文件，正在初始化..."
  cd /app
  /usr/local/bin/file-proxy-server --config-generate
  chown nobody:nobody "/app/config.yaml"
  echo "生成默认配置到 /app/config.yaml"
else
  echo "检测到现有配置文件: /app/config.yaml"
fi

echo "=== 启动应用 ==="
exec "$@"
