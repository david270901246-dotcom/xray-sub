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
 
...(truncated)...
