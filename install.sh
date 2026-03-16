#!/bin/bash

# Attia Panel - Debian 11 一键部署脚本
# 颜色输出
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${GREEN}=================================================${RESET}"
echo -e "${GREEN}      欢迎使用 Attia 面板一键部署脚本 (Debian 11)   ${RESET}"
echo -e "${GREEN}=================================================${RESET}"

# 1. 检查 root 权限
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 root 权限运行此脚本！(sudo ./install.sh)${RESET}"
  exit 1
fi

# 获取当前脚本所在目录作为项目目录
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 2. 更新系统并安装必要的系统环境
echo -e "${YELLOW}[1/5] 正在更新系统并安装核心环境 (Python3, Nginx, Certbot)...${RESET}"
apt update -y
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx curl fuser

# 3. 安装 Python 依赖
echo -e "${YELLOW}[2/5] 正在安装 Python 依赖库...${RESET}"
pip3 install -r "$PROJECT_DIR/requirements.txt"

# 4. 配置 Systemd 守护进程
echo -e "${YELLOW}[3/5] 正在配置系统守护进程 (Systemd)...${RESET}"
cat > /etc/systemd/system/attia.service <<EOF
[Unit]
Description=Attia Subscription Gateway
After=network.target

[Service]
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/python3 $PROJECT_DIR/attia.py
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=attia

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable attia
fuser -k 5005/tcp 2>/dev/null
systemctl start attia

echo -e "${GREEN}Attia 后端服务已在 5005 端口启动并设置开机自启！${RESET}"

# 5. 域名与 SSL 配置
echo -e "${YELLOW}[4/5] Nginx 反向代理与 SSL 证书配置${RESET}"
read -p "请输入您已解析到本机的域名 (例如 attia.yourdomain.com，如暂不配置请直接回车跳过): " DOMAIN

if [ -n "$DOMAIN" ]; then
    echo -e "${YELLOW}正在为 $DOMAIN 配置 Nginx...${RESET}"
    cat > /etc/nginx/sites-available/attia <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:5005;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    ln -sf /etc/nginx/sites-available/attia /etc/nginx/sites-enabled/
    systemctl restart nginx

    echo -e "${YELLOW}[5/5] 正在向 Let's Encrypt 申请 SSL 证书...${RESET}"
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m admin@"$DOMAIN"
    
    echo -e "${GREEN}=================================================${RESET}"
    echo -e "${GREEN}部署完成！请访问: https://$DOMAIN${RESET}"
    echo -e "${GREEN}首位注册的用户将自动成为超级管理员。${RESET}"
else
    echo -e "${GREEN}=================================================${RESET}"
    echo -e "${GREEN}部署完成！您跳过了域名配置。${RESET}"
    echo -e "${GREEN}现在可通过 http://服务器IP:5005 访问面板。${RESET}"
fi
echo -e "${GREEN}=================================================${RESET}"