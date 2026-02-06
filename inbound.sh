#!/bin/bash

# Clear screen
clear

# --- Banner Section ---
echo "------------------------------------------------------------"
echo -e "\e[1;36m"
echo "   1011 Ultimate Setup (Sing-box Core)"
echo "------------------------------------------------------------"
echo -e "\e[1;33m  Installing All Protocols:\e[0m"
echo "  🚀 Hysteria 2 (UDP - Port 8443)"
echo "  🔹 VLESS Reality (TCP - Port 443)"
echo "  🔹 VLESS WS TLS (TCP - Port 2083)"
echo "  🔹 Trojan TLS (TCP - Port 2053)"
echo "  🔹 Shadowsocks (TCP/UDP - Port 1080)"
echo "--------------------------------------------------"

# --- Check Domain ---
DOMAIN=$(ls -1 /var/lib/marzban/certs/ 2>/dev/null | head -n 1)
if [ -z "$DOMAIN" ]; then
    echo -e "\e[1;31m❌ Error: Domain folder ရှာမတွေ့ပါ။ install.sh နဲ့ အရင် SSL setup လုပ်ထားဖို့ လိုပါတယ်။\e[0m"
    exit 1
else
    echo -e "\e[1;32m✅ Domain found: $DOMAIN\e[0m"
fi

echo "🔑 Generating Keys..."
# Install Xray for Key Generation only (Temporary)
apt update && apt install unzip -y &>/dev/null
curl -L -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip &>/dev/null
unzip -o /tmp/xray.zip xray -d /tmp/ &>/dev/null
chmod +x /tmp/xray
KEYS=$(/tmp/xray x25519)

PRIV=$(echo "$KEYS" | grep "Private key" | cut -d ' ' -f 3)
PUB=$(echo "$KEYS" | grep "Public key" | cut -d ' ' -f 3)
SID=$(openssl rand -hex 4)

if [ -z "$PRIV" ]; then
    echo -e "\e[1;31m❌ Error: Keys ထုတ်လို့ မရခဲ့ပါ။\e[0m"
    exit 1
fi

echo -e "\e[1;32m✅ Keys Generated.\e[0m"

# --- Switch Marzban to Sing-box Core ---
# We create config.json instead of xray_config.json
# Marzban detects config.json and switches to Sing-box automatically

cat <<EOF > /var/lib/marzban/config.json
{
  "log": {
    "level": "warn",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "HYSTERIA-IN",
      "listen": "::",
      "listen_port": 8443,
      "users": [],
      "tls": {
        "enabled": true,
        "certificate_path": "/var/lib/marzban/certs/$DOMAIN/fullchain.pem",
        "key_path": "/var/lib/marzban/certs/$DOMAIN/privkey.pem"
      }
    },
    {
      "type": "vless",
      "tag": "VLESS REALITY",
      "listen": "::",
      "listen_port": 443,
      "users": [],
      "tls": {
        "enabled": true,
        "server_name": "www.cloudflare.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.cloudflare.com",
            "server_port": 443
          },
          "private_key": "$PRIV",
          "short_id": [
            "$SID"
          ]
        }
      }
    },
    {
      "type": "vless",
      "tag": "VLESS WS TLS",
      "listen": "::",
      "listen_port": 2083,
      "users": [],
      "transport": {
        "type": "ws",
        "path": "/vless"
      },
      "tls": {
        "enabled": true,
        "certificate_path": "/var/lib/marzban/certs/$DOMAIN/fullchain.pem",
        "key_path": "/var/lib/marzban/certs/$DOMAIN/privkey.pem"
      }
    },
    {
      "type": "trojan",
      "tag": "TROJAN TLS",
      "listen": "::",
      "listen_port": 2053,
      "users": [],
      "tls": {
        "enabled": true,
        "certificate_path": "/var/lib/marzban/certs/$DOMAIN/fullchain.pem",
        "key_path": "/var/lib/marzban/certs/$DOMAIN/privkey.pem"
      }
    },
    {
      "type": "shadowsocks",
      "tag": "SHADOWSOCKS",
      "listen": "::",
      "listen_port": 1080,
      "method": "2022-blake3-aes-128-gcm",
      "users": []
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "DIRECT"
    },
    {
      "type": "block",
      "tag": "BLOCK"
    }
  ]
}
EOF

# --- Clean up Xray config to avoid conflicts ---
rm -f /var/lib/marzban/xray_config.json

echo "📝 Updating .env to support Hysteria..."
# Ensure default setup is correct
sed -i 's/XRAY_JSON/CONFIG_JSON/g' /opt/marzban/.env 2>/dev/null

echo "✅ JSON File Updated (Sing-box Format)."
echo "🔄 Restarting Marzban..."
marzban restart

# Cleanup
rm -rf /tmp/xray.zip /tmp/xray 2>/dev/null

echo "--------------------------------------------------"
echo -e "\e[1;32m🔥 1011 Setup Complete! (Hysteria 2 + All) 🔥\e[0m"
echo -e "\e[1;33m INFO: \e[0m Marzban သည် ယခု Sing-box Core ဖြင့် Run နေပါသည်။"
echo "--------------------------------------------------"
