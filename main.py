#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xray 手机订阅服务器
 - 从多个 GitHub 免费节点源抓取 Trojan/VLESS/VMess 节点
 - 生成 v2rayNG / Clash Meta 兼容的订阅内容
 - 自动测速，按速度排序

Railway 部署：
   Railway 会自动注入 PORT 环境变量（随机端口）
   脚本必须读取 PORT 并绑定 0.0.0.0 才能被公网访问
   无需 requirements.txt（只用 Python 标准库）
"""

import http.server
import socketserver
import threading
import sys
import os
import re
import json
import time
import socket
import ssl
import hashlib
import base64
import urllib.request
import urllib.parse
import random

# ============================================================
# 配置（Railway 关键：PORT 读环境变量，BIND 必须是 0.0.0.0）
# ============================================================
PORT = int(os.environ.get("PORT", 8080))
BIND = os.environ.get("BIND", "0.0.0.0")

# 节点源
NODE_SOURCES = [
    ("peasoft/NoMoreWalls", "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml", "clash"),
    ("ripaojiedian/freenode", "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash", "clash"),
    ("Pawdroid/Free-servers", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", "base64"),
    ("freefq/free", "https://raw.githubusercontent.com/freefq/free/master/v2", "base64"),
    ("aiboboxx/v2rayfree", "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/clash.yaml", "clash"),
    ("ermaozi/get_subscribe", "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml", "clash"),
]

# 测试参数
TCP_TIMEOUT = 3
MAX_TEST_NODES = 30
MAX_SUBSCRIBE_NODES = 50

# 缓存
_nodes_cache = None
_cache_time = 0
CACHE_TTL = 300


# ============================================================
# 节点解析
# ============================================================

def fetch_url(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def fetch_with_mirror(url):
    content = fetch_url(url, timeout=10)
    if content and len(content) > 50:
        return content
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)", url)
    if not m:
        return None
    owner, repo, branch, path = m.group(1), m.group(2), m.group(3), m.group(4)
    repo_full = f"{owner}/{repo}"
    for cdn in ["https://cdn.jsdelivr.net/gh/{repo}@{branch}/{path}",
                "https://fastly.jsdelivr.net/gh/{repo}@{branch}/{path}"]:
        content = fetch_url(cdn.format(repo=repo_full, branch=branch, path=path), timeout=10)
        if content and len(content) > 50:
            return content
    for proxy in ["https://ghp.ci/{url}", "https://ghproxy.net/{url}"]:
        content = fetch_url(proxy.format(url=url), timeout=10)
        if content and len(content) > 50:
            return content
    return None


def clean_sni(sni):
    if not sni:
        return sni
    try:
        decoded = urllib.parse.unquote(sni)
        if "%" in decoded:
            decoded = urllib.parse.unquote(decoded)
    except Exception:
        decoded = sni
    return decoded.split("/")[0] if "/" in decoded else decoded


def parse_node_url(url):
    if url.startswith("trojan://"):
        return parse_trojan(url)
    elif url.startswith("vless://"):
        return parse_vless(url)
    elif url.startswith("vmess://"):
        return parse_vmess(url)
    return None


def parse_trojan(url):
    try:
        rest = url[len("trojan://"):]
        name = ""
        if "#" in rest:
            rest, name = rest.rsplit("#", 1)
            name = urllib.parse.unquote(name)
        params = {}
        if "?" in rest:
            rest, query = rest.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query))
        if "@" not in rest:
            return None
        password, hostport = rest.rsplit("@", 1)
        if ":" not in hostport:
            return None
        host, port_str = hostport.rsplit(":", 1)
        return {
            "protocol": "trojan",
            "address": host.strip(),
            "port": int(port_str),
            "password": urllib.parse.unquote(password),
            "sni": clean_sni(params.get("sni", host)),
            "network": params.get("type", "tcp"),
            "ws_path": params.get("path", "/"),
            "ws_host": params.get("host", host),
            "security": "tls",
            "name": name or f"trojan-{host}:{port_str}",
        }
    except Exception:
        return None


def parse_vless(url):
    try:
        rest = url[len("vless://"):]
        name = ""
        if "#" in rest:
            rest, name = rest.rsplit("#", 1)
            name = urllib.parse.unquote(name)
        params = {}
        if "?" in rest:
            rest, query = rest.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query))
        if "@" not in rest:
            return None
        uuid_val, hostport = rest.rsplit("@", 1)
        if ":" not in hostport:
            return None
        host, port_str = hostport.rsplit(":", 1)
        return {
            "protocol": "vless",
            "address": host.strip(),
            "port": int(port_str),
            "uuid": uuid_val.strip(),
            "sni": clean_sni(params.get("sni", params.get("host", host))),
            "network": params.get("type", "tcp"),
            "ws_path": params.get("path", "/"),
            "ws_host": params.get("host", host),
            "security": params.get("security", "tls"),
            "name": name or f"vless-{host}:{port_str}",
        }
    except Exception:
        return None


def parse_vmess(url):
    try:
        encoded = url[len("vmess://"):]
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding
        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        cfg = json.loads(decoded)
        return {
            "protocol": "vmess",
            "address": cfg.get("add", ""),
            "port": int(cfg.get("port", 0)),
            "uuid": cfg.get("id", ""),
            "alterId": int(cfg.get("aid", 0)),
            "sni": clean_sni(cfg.get("sni", cfg.get("host", cfg.get("add", "")))),
            "network": cfg.get("net", "tcp"),
            "ws_path": cfg.get("path", "/"),
            "ws_host": cfg.get("host", cfg.get("add", "")),
            "security": "tls" if cfg.get("tls") == "tls" else "none",
            "name": cfg.get("ps", f"vmess-{cfg.get('add')}:{cfg.get('port')}"),
        }
    except Exception:
        return None


def parse_base64_sub(content):
    nodes = []
    try:
        decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
    except Exception:
        decoded = content
    for line in decoded.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        node = parse_node_url(line)
        if node:
            nodes.append(node)
    return nodes


def parse_clash(content):
    nodes = []
    in_proxies = False
    proxies_raw = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "proxies:" or stripped.startswith("proxies:"):
            in_proxies = True
            continue
        if in_proxies and stripped and not line.startswith(" ") and not line.startswith("-"):
            in_proxies = False
            continue
        if in_proxies and stripped:
            proxies_raw.append(stripped)

    current = {}
    for line in proxies_raw:
        if line.startswith("- "):
            if current:
                node = clash_to_node(current)
                if node:
                    nodes.append(node)
                current = {}
            line = line[2:]
            if line.startswith("{") and line.endswith("}"):
                inline = line[1:-1]
                current = parse_clash_inline(inline)
                node = clash_to_node(current)
                if node:
                    nodes.append(node)
                current = {}
            else:
                if ":" in line:
                    key, val = line.split(":", 1)
                    current[key.strip()] = val.strip().strip('"').strip("'")
        else:
            if ":" in line:
                key, val = line.split(":", 1)
                current[key.strip()] = val.strip().strip('"').strip("'")
    if current:
        node = clash_to_node(current)
        if node:
            nodes.append(node)
    return nodes


def parse_clash_inline(s):
    result = {}
    parts = []
    current = ""
    in_quote = False
    for ch in s:
        if ch in '"\'':
            in_quote = not in_quote
        elif ch == "," and not in_quote:
            parts.append(current)
            current = ""
            continue
        current += ch
    if current:
        parts.append(current)
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def clash_to_node(p):
    ptype = p.get("type", "").lower()
    server = p.get("server", "")
    if ptype == "trojan":
        return {
            "protocol": "trojan",
            "address": server,
            "port": int(p.get("port", 0) or 0),
            "password": p.get("password", ""),
            "sni": clean_sni(p.get("sni", server)),
            "network": "tcp",
            "ws_path": "/",
            "ws_host": server,
            "security": "tls",
            "name": p.get("name", ""),
        }
    elif ptype == "vless":
        return {
            "protocol": "vless",
            "address": server,
            "port": int(p.get("port", 0) or 0),
            "uuid": p.get("uuid", ""),
            "sni": clean_sni(p.get("sni", p.get("servername", server))),
            "network": p.get("network", "tcp"),
            "ws_path": p.get("ws-opts-path", p.get("path", "/")),
            "ws_host": p.get("ws-opts-host", server),
            "security": "tls" if p.get("tls") in ("true", True) else "none",
            "name": p.get("name", ""),
        }
    elif ptype == "vmess":
        return {
            "protocol": "vmess",
            "address": server,
            "port": int(p.get("port", 0) or 0),
            "uuid": p.get("uuid", ""),
            "alterId": int(p.get("alterId", 0) or 0),
            "sni": clean_sni(p.get("sni", server)),
            "network": p.get("network", "tcp"),
            "ws_path": p.get("ws-opts-path", p.get("path", "/")),
            "ws_host": p.get("ws-opts-host", server),
            "security": "tls" if p.get("tls") in ("true", True) else "none",
            "name": p.get("name", ""),
        }
    return None


def parse_nodes(content, fmt):
    if fmt == "base64":
        return parse_base64_sub(content)
    elif fmt == "clash":
        return parse_clash(content)
    return []


def fetch_all_nodes():
    all_nodes = []
    for name, url, fmt in NODE_SOURCES:
        print(f" 抓取 {name}...")
        content = fetch_with_mirror(url)
        if not content:
            print(f" [X] 失败")
            continue
        nodes = parse_nodes(content, fmt)
        print(f" [OK] {len(nodes)} 个节点")
        all_nodes.extend(nodes)

    seen = set()
    unique = []
    for n in all_nodes:
        key = f"{n['protocol']}:{n['address']}:{n['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(n)
    print(f" 去重后共 {len(unique)} 个节点")
    return unique


# ============================================================
# 速度测试
# ============================================================

def test_tcp_speed(host, port, timeout=TCP_TIMEOUT):
    try:
        t = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        latency = int((time.time() - t) * 1000)
        sock.close()
        return latency
    except Exception:
        return 99999


def test_and_sort_nodes(nodes):
    print(f"\n 开始测速（共 {len(nodes)} 个节点）...")
    results = []
    for i, node in enumerate(nodes[:MAX_TEST_NODES]):
        latency = test_tcp_speed(node["address"], node["port"])
        node["latency"] = latency
        results.append(node)
        print(f" [{i+1}/{min(len(nodes), MAX_TEST_NODES)}] {node['protocol']:6s} {node['address']:30s}:{node['port']:5d} {latency:5d}ms")

    results.sort(key=lambda x: x["latency"])
    print(f"\n 测速完成！延迟最低的 5 个节点：")
    for n in results[:5]:
        print(f" {n['protocol']:6s} {n['address']:30s}:{n['port']:5d} {n['latency']}ms")

    return results


# ============================================================
# 订阅内容生成
# ============================================================

def node_to_v2rayng(n):
    ob = {"tag": "proxy", "protocol": n["protocol"]}

    if n["protocol"] == "trojan":
        ob["settings"] = {"servers": [{"address": n["address"], "port": n["port"], "password": n["password"]}]}
    elif n["protocol"] == "vless":
        ob["settings"] = {"vnext": [{"address": n["address"], "port": n["port"], "users": [{"id": n["uuid"], "encryption": "none"}]}]}
    elif n["protocol"] == "vmess":
        ob["settings"] = {"vnext": [{"address": n["address"], "port": n["port"], "users": [{"id": n["uuid"], "alterId": n.get("alterId", 0), "security": "auto"}]}]}

    network = n.get("network", "tcp")
    use_tls = n.get("security", "tls") == "tls" or n["protocol"] == "trojan"
    stream = {"network": network}

    if use_tls:
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": n.get("sni", n["address"]), "fingerprint": "chrome"}
    else:
        stream["security"] = "none"

    if network == "ws":
        ws = {"path": n.get("ws_path", "/")}
        if n.get("ws_host"):
            ws["headers"] = {"Host": n["ws_host"]}
        stream["wsSettings"] = ws

    ob["streamSettings"] = stream
    return ob


def generate_v2rayng_content(nodes):
    outbounds = [node_to_v2rayng(n) for n in nodes]
    config = {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["8.8.8.8", "1.1.1.1", "localhost"]},
        "inbounds": [
            {"tag": "socks", "port": 1080, "listen": "0.0.0.0", "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http", "port": 1081, "listen": "0.0.0.0", "protocol": "http", "settings": {}},
        ],
        "outbounds": outbounds + [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}]
        }
    }
    content = json.dumps(config, ensure_ascii=False, indent=2)
    return base64.b64encode(content.encode("utf-8")).decode("ascii")


def generate_clash_content(nodes):
    proxies_yaml = []
    for n in nodes:
        pname = n.get("name") or f"{n['protocol']}-{n['address']}:{n['port']}"
        if n["protocol"] == "trojan":
            proxies_yaml.append(
                f" - name: \"{pname}\"\n"
                f" type: trojan\n"
                f" server: {n['address']}\n"
                f" port: {n['port']}\n"
                f" password: {n['password']}\n"
                f" sni: {n.get('sni', n['address'])}\n"
                f" skip-cert-verify: false\n"
                f" udp: true\n"
            )
        elif n["protocol"] == "vless":
            sni = n.get("sni", n["address"])
            network = n.get("network", "tcp")
            proxies_yaml.append(
                f" - name: \"{pname}\"\n"
                f" type: vless\n"
                f" server: {n['address']}\n"
                f" port: {n['port']}\n"
                f" uuid: {n['uuid']}\n"
                f" flow: ''\n"
                f" client-fingerprint: chrome\n"
                f" tls: true\n"
                f" sni: {sni}\n"
                f" network: {network}\n"
            )
        elif n["protocol"] == "vmess":
            sni = n.get("sni", n["address"])
            network = n.get("network", "tcp")
            ws = ""
            if network == "ws":
                ws = f" ws-opts:\n  path: {n.get('ws_path','/')}\n  headers:\n    Host: {n.get('ws_host', n['address'])}\n"
            proxies_yaml.append(
                f" - name: \"{pname}\"\n"
                f" type: vmess\n"
                f" server: {n['address']}\n"
                f" port: {n['port']}\n"
                f" uuid: {n['uuid']}\n"
                f" alterId: {n.get('alterId', 0)}\n"
                f" cipher: auto\n"
                f" tls: {n.get('security','none') == 'tls'}\n"
                f" servername: {sni}\n"
                f" network: {network}\n"
                f"{ws}"
            )

    proxies_text = "\n".join(proxies_yaml)
    return f"""port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
{proxies_text}

proxy-groups:
 - name: 🚀 节点选择
   type: select
   proxies:
     - 自动选择
     - 手动选择
{''.join(f'     - "{n.get("name") or f"{n["protocol"]}-{n["address"]}"}"\n' for n in nodes[:20])}
 - name: 自动选择
   type: url-test
   proxies:
{''.join(f'     - "{n.get("name") or f"{n["protocol"]}-{n["address"]}"}"\n' for n in nodes[:10])}
   url: "http://www.gstatic.com/generate_204"
   interval: 300
 - name: 手动选择
   type: select

rules:
 - GEOIP,CN,DIRECT
 - MATCH,🚀 节点选择
"""


# ============================================================
# HTTP 服务器
# ============================================================

class SubHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f" [{self.log_date_time_string()}] {fmt % args}")

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_html()
        elif self.path.startswith("/sub/"):
            self.send_subscription()
        elif self.path.startswith("/nodes.json"):
            self.send_nodes_json()
        else:
            self.send_error(404)

    def send_subscription(self):
        global _nodes_cache, _cache_time
        now = time.time()
        if _nodes_cache is None or now - _cache_time > CACHE_TTL:
            print("\n[订阅] 缓存过期，重新抓取节点...")
            nodes = fetch_all_nodes()
            sorted_nodes = test_and_sort_nodes(nodes)
            _nodes_cache = sorted_nodes
            _cache_time = now
        else:
            print(f"\n[订阅] 使用缓存（{len(_nodes_cache)} 个节点，{(now-_cache_time):.0f}s 前刷新）")

        selected = _nodes_cache[:MAX_SUBSCRIBE_NODES]

        if self.path.endswith("/v2rayng"):
            content = generate_v2rayng_content(selected)
        elif self.path.endswith("/clash"):
            content = generate_clash_content(selected)
        else:
            content = generate_v2rayng_content(selected)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="subscription"')
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Profile-Update-Interval", "6")
        self.send_header("Subscription-Userinfo", "upload=0; download=0; total=107374182400000; expire=9999999999")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))
        print(f" → 发送订阅（{len(selected)} 节点，{len(content)} 字节）")

    def send_nodes_json(self):
        global _nodes_cache
        if _nodes_cache:
            nodes = _nodes_cache[:MAX_SUBSCRIBE_NODES]
        else:
            nodes = fetch_all_nodes()
        content = json.dumps(nodes, ensure_ascii=False, indent=2)
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def send_html(self):
        public_host = os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("PUBLIC_HOST")
        if public_host:
            base_url = f"https://{public_host}"
        else:
            local_ip = "127.0.0.1"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass
            base_url = f"http://{local_ip}:{PORT}"

        html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Xray 手机订阅服务</title>
<style>
 body{{font-family:'Microsoft YaHei',sans-serif;max-width:700px;margin:0 auto;padding:20px;background:#f5f5f5}}
 h1{{color:#333;text-align:center}}
 .card{{background:#fff;border-radius:12px;padding:24px;margin:16px 0;box-shadow:0 2px 8px rgba(0,0,0,.1)}}
 .label{{color:#888;font-size:13px;margin-bottom:4px}}
 .url{{background:#f0f0f0;padding:12px;border-radius:8px;font-size:14px;word-break:break-all;color:#0066cc}}
 .btn{{display:inline-block;background:#0066cc;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;margin:8px 4px}}
 .btn:hover{{background:#0055aa}}
 .btn-green{{background:#28a745}}
</style>
</head>
<body>
<h1>📡 Xray 手机订阅服务</h1>

<div class="card">
 <div class="label">v2rayNG 订阅地址</div>
 <div class="url">{base_url}/sub/v2rayng</div>
 <div style="margin-top:12px">
 <a class="btn" href="/sub/v2rayng" target="_blank">🔗 打开订阅</a>
 </div>
</div>

<div class="card">
 <div class="label">Clash Meta / Clash Verge 订阅地址</div>
 <div class="url">{base_url}/sub/clash</div>
 <div style="margin-top:12px">
 <a class="btn btn-green" href="/sub/clash" target="_blank">🔗 打开订阅</a>
 </div>
</div>

<div class="card">
 <div class="label">📱 v2rayNG 添加订阅步骤</div>
 <div style="font-size:13px;color:#555;margin-top:8px;line-height:1.8">
 1. 手机安装 <b>v2rayNG</b><br>
 2. 右上角 <b>⋮</b> → <b>订阅设置</b> → <b>添加订阅URL</b><br>
 3. 粘贴上面的 v2rayNG 订阅地址<br>
 4. 返回主界面 → <b>更新订阅</b>（右上角↻）<br>
 5. 选择节点 → 点击连接 ✅
 </div>
</div>

<div class="card">
 <div class="label">⚙️ 服务器配置</div>
 <div style="font-size:13px;color:#666;margin-top:8px">
 监听端口：<b>{PORT}</b><br>
 绑定地址：<b>{BIND}</b><br>
 缓存时间：<b>{CACHE_TTL}秒</b>
 </div>
</div>
</body>
</html>"""
        content = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    global PORT, BIND

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("--port="):
            PORT = int(arg.split("=", 1)[1])
        elif arg == "--bind":
            if i + 1 < len(args):
                BIND = args[i + 1]
                i += 1
        elif arg == "--test":
            print("=== 仅测速模式 ===")
            nodes = fetch_all_nodes()
            sorted_nodes = test_and_sort_nodes(nodes)
            print(f"\n速度最快的 10 个节点：")
            for n in sorted_nodes[:10]:
                print(f" {n['protocol']:6s} {n['address']:30s}:{n['port']:5d} {n['latency']}ms {n.get('name','')}")
            return
        elif arg == "--help":
            print(__doc__)
            return
        i += 1

    local_ip = get_local_ip()

    print("=" * 60)
    print(" Xray 手机订阅服务器")
    print("=" * 60)
    print(f"\n 📡 本地订阅地址（电脑浏览器打开）：")
    print(f" http://127.0.0.1:{PORT}/")
    if not os.environ.get("RAILWAY_PUBLIC_DOMAIN"):
        print(f"\n 📱 手机订阅地址（同 WiFi 下复制）：")
        print(f" v2rayNG: http://{local_ip}:{PORT}/sub/v2rayng")
        print(f" Clash: http://{local_ip}:{PORT}/sub/clash")
    else:
        print(f"\n 🌐 公网地址：")
        print(f" https://{os.environ.get('RAILWAY_PUBLIC_DOMAIN')}/")
    print("=" * 60)

    print("\n[启动] 预抓取节点...")
    try:
        nodes = fetch_all_nodes()
        sorted_nodes = test_and_sort_nodes(nodes)
        global _nodes_cache, _cache_time
        _nodes_cache = sorted_nodes
        _cache_time = time.time()
    except Exception as e:
        print(f"[警告] 预抓取失败：{e}，将在首次请求时重试")

    class ReuseAddrServer(socketserver.TCPServer):
        allow_reuse_address = True
        request_queue_size = 16

    with ReuseAddrServer((BIND, PORT), SubHandler) as httpd:
        print(f"\n[就绪] 服务运行中 http://{BIND}:{PORT}/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[停止] 服务已关闭")


if __name__ == "__main__":
    main()
