# -*- coding: UTF-8 -*-
"""
Author: Linzjian666
Date: 2024-01-13 11:29:53
LastEditors: Linzjian666
LastEditTime: 2024-02-04 17:09:32
"""
import yaml
import json
import urllib.request
import logging
import geoip2.database
import socket
import re
import base64

def process_urls(urls_file, method):
    try:
        with open(urls_file, 'r') as f:
            urls = f.read().splitlines()

        for index, url in enumerate(urls):
            try:
                response = urllib.request.urlopen(url)
                data = response.read().decode('utf-8')
                method(data, index)
            except Exception as e:
                logging.error(f"处理{url}时遇到错误: {e}")
    except Exception as e:
        logging.error(f"读取{urls_file}时遇到错误: {e}")
        return

def process_clash_meta(data, index):
    try:
        content = yaml.safe_load(data)
        proxies = content.get('proxies', [])
        
        for i, proxy in enumerate(proxies):
            unique_key = None
            if "network" in proxy and proxy["network"] == "ws":
                unique_key = f"{proxy['server']}:{proxy['port']}-{proxy['ws-opts']['headers']['host']}-ws"
            else:
                unique_key = f"{proxy['server']}:{proxy['port']}-{proxy['type']}"

            # 关键修复：检查代理是否已存在，如果存在则更新配置，而不是跳过
            if unique_key in servers_map:
                existing_proxy = servers_map[unique_key]
                # 仅更新需要修改的字段，以保留原始代理的名称等信息
                if proxy['type'] == 'tuic':
                    existing_proxy['skip-cert-verify'] = proxy.get('skip-cert-verify', False)
                # ...可以添加其他需要更新的字段
            else:
                location = get_physical_location(proxy['server'])
                proxy['name'] = f"{location}-{proxy['type']} | {index}-{i+1}"
                
                if proxy['type'] == "tuic":
                    proxy['uuid'] = proxy.get('uuid', '')
                    proxy['password'] = proxy.get('password', '')
                    proxy['sni'] = proxy.get('sni', '')
                    proxy['alpn'] = proxy.get('alpn', [])
                    # 确保从 YAML 读取的布尔值被正确存储
                    proxy['skip-cert-verify'] = proxy.get('skip-cert-verify', False)
                    proxy['udp-relay-mode'] = proxy.get('udp-relay-mode', 'native')
                    proxy['congestion-controller'] = proxy.get('congestion-controller', 'bbr')
                    proxy['reduce-rtt'] = proxy.get('reduce-rtt', False)
                
                servers_map[unique_key] = proxy
    except Exception as e:
        logging.error(f"处理Clash Meta配置{index}时遇到错误: {e}")

def process_hysteria(data, index):
    try:
        content = json.loads(data)
        auth = content['auth_str']
        server_ports_slt = content['server'].split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        ports_slt = ports.split(',')
        server_port = int(ports_slt[0])
        mport = int(ports_slt[1]) if len(ports_slt) > 1 else server_port
        fast_open = content.get('fast_open', True)
        insecure = content['insecure']
        sni = content['server_name']
        alpn = content['alpn']
        protocol = content['protocol']
        location = get_physical_location(server)
        name = f"{location}-Hysteria | {index}-0"
        
        unique_key = f"{server}:{server_port}-hysteria"
        
        if unique_key not in servers_map:
            proxy = {
                "name": name,
                "type": "hysteria",
                "server": server,
                "port": server_port,
                "ports": mport,
                "auth-str": auth,
                "up": 80,
                "down": 100,
                "fast-open": fast_open,
                "protocol": protocol,
                "sni": sni,
                "skip-cert-verify": insecure,
                "alpn": [alpn]
            }
            servers_map[unique_key] = proxy

    except Exception as e:
        logging.error(f"处理Hysteria配置{index}时遇到错误: {e}")
        
def process_hysteria2(data, index):
    try:
        content = json.loads(data)
        auth = content['auth']
        server_ports_slt = content['server'].split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        server_port = int(ports.split(',')[0])
        insecure = content['tls']['insecure']
        sni = content['tls']['sni']
        location = get_physical_location(server)
        name = f"{location}-Hysteria2 | {index}-0"
        
        unique_key = f"{server}:{server_port}-hysteria2"
        
        if unique_key not in servers_map:
            proxy = {
                "name": name,
                "type": "hysteria2",
                "server": server,
                "port": server_port,
                "password": auth,
                "sni": sni,
                "skip-cert-verify": insecure
            }
            servers_map[unique_key] = proxy
            
    except Exception as e:
        logging.error(f"处理Hysteria2配置{index}时遇到错误: {e}")

def process_xray(data, index):
    try:
        content = json.loads(data)
        outbounds = content['outbounds']
        pending_proxy = outbounds[0]
        proxy_type = pending_proxy['protocol']
        
        if proxy_type == "vmess":
            server = pending_proxy['settings']['vnext'][0]['address']
            port = pending_proxy['settings']['vnext'][0]['port']
            uuid = pending_proxy['settings']['vnext'][0]['users'][0]['id']
            alterId = pending_proxy['settings']['vnext'][0]['users'][0]['alterId']
            cipher = pending_proxy['settings']['vnext'][0]['users'][0]['security']
            network = pending_proxy['streamSettings']['network']
            security = pending_proxy['streamSettings'].get('security', "none")
            location = get_physical_location(server)
            name = f"{location}-{proxy_type} | {index}-0"
            tls = security != "none"
            sni = pending_proxy['streamSettings'].get('tlsSettings', {}).get('serverName', "")
            allowInsecure = pending_proxy['streamSettings'].get('tlsSettings', {}).get('allowInsecure', False)
            
            if network in ['tcp','ws','grpc','h2']:
                proxy = {
                    "name": name,
                    "type": "vmess",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "alterId": alterId,
                    "cipher": cipher,
                    "tls": tls,
                    "servername": sni,
                    "skip-cert-verify": allowInsecure,
                    "network": network,
                    "ws-opts": {"path": pending_proxy['streamSettings'].get('wsSettings', {}).get('path', ""), "headers": pending_proxy['streamSettings'].get('wsSettings', {}).get('headers', {})},
                    "grpc-opts": {"serviceName": pending_proxy['streamSettings'].get('grpcSettings', {}).get('serviceName', "/")},
                    "h2-opts": {"path": pending_proxy['streamSettings'].get('httpSettings', {}).get('path', "/"), "host": pending_proxy['streamSettings'].get('httpSettings', {}).get('host', [])}
                }
            else:
                logging.error(f"处理Xray配置{index}时遇到错误: 不支持的VMess传输协议: {network}")
                return
        
        elif proxy_type == "vless":
            server = pending_proxy['settings']['vnext'][0]['address']
            port = pending_proxy['settings']['vnext'][0]['port']
            uuid = pending_proxy['settings']['vnext'][0]['users'][0]['id']
            flow = pending_proxy['settings']['vnext'][0]['users'][0].get('flow', "")
            security = pending_proxy['streamSettings'].get('security', "none")
            network = pending_proxy['streamSettings']['network']
            location = get_physical_location(server)
            name = f"{location}-{proxy_type} | {index}-0"
            tls = security != "none"

            if security == "reality":
                realitySettings = pending_proxy['streamSettings'].get('realitySettings', {})
                proxy = {
                    "name": name,
                    "type": "vless",
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "flow": flow,
                    "tls": tls,
                    "servername": realitySettings.get('serverName', ""),
                    "network": network,
                    "client-fingerprint": realitySettings['fingerprint'],
                    "grpc-opts": {"grpc-service-name": pending_proxy['streamSettings'].get('grpcSettings', {}).get('serviceName', "/")},
                    "reality-opts": {"public-key": realitySettings['publicKey'], "short-id": realitySettings.get('shortId', "")},
                    "xhttp-opts": {"path": pending_proxy['streamSettings'].get('xhttpSettings', {}).get('path', "")}
                }
            else:
                if network in ['tcp','ws','grpc']:
                    proxy = {
                        "name": name,
                        "type": "vless",
                        "server": server,
                        "port": port,
                        "uuid": uuid,
                        "tls": tls,
                        "servername": pending_proxy['streamSettings'].get('tlsSettings', {}).get('serverName', ""),
                        "skip-cert-verify": pending_proxy['streamSettings'].get('tlsSettings', {}).get('allowInsecure', False),
                        "network": network,
                        "ws-opts": {"path": pending_proxy['streamSettings'].get('wsSettings', {}).get('path', ""), "headers": pending_proxy['streamSettings'].get('wsSettings', {}).get('headers', {})},
                        "grpc-opts": {"serviceName": pending_proxy['streamSettings'].get('grpcSettings', {}).get('serviceName', "/")}
                    }
                else:
                    logging.error(f"处理Xray配置{index}时遇到错误: 不支持的VLESS传输协议: {network}")
                    return
        else:
            logging.error(f"处理Xray配置{index}时遇到错误: 不支持的传输协议: {proxy_type}")
            return
        
        unique_key = f"{proxy['server']}:{proxy['port']}-{proxy['type']}"
        if unique_key not in servers_map:
            servers_map[unique_key] = proxy
            
    except Exception as e:
        logging.error(f"处理Xray配置{index}时遇到错误: {e}")

def get_physical_location(address):
    address = re.sub(":.*", "", address)
    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader("GeoLite2-City.mmdb")
        response = reader.city(ip_address)
        country = response.country.iso_code
        flag_emoji = "".join([chr(ord(c) + ord("🇦") - ord("A")) for c in country])
        if flag_emoji == "🇹🇼":
            flag_emoji = "🇨🇳"
        return f"{flag_emoji} {country}"
    except Exception as e:
        return "🏳 Unknown"
    
def write_clash_meta_profile(template_file, output_file, extracted_proxies):
    with open(template_file, 'r', encoding='utf-8') as f:
        profile = yaml.safe_load(f)
    
    profile['proxies'] = extracted_proxies
    
    for group in profile['proxy-groups']:
        if group['name'] in ['🚀 节点选择','♻️ 自动选择','🔯 故障转移','☁ WARP前置节点','📺 巴哈姆特','📺 哔哩哔哩','🌏 国内媒体','🌍 国外媒体','📲 电报信息','Ⓜ️ 微软云盘','Ⓜ️ 微软服务','🍎 苹果服务','📢 谷歌FCM','🤖 OpenAI','🐟 漏网之鱼']:
            group['proxies'] = [proxy['name'] for proxy in extracted_proxies]
    
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(profile, f, sort_keys=False, allow_unicode=True)

def write_proxy_urls_file(output_file, proxies):
    proxy_urls = []
    for proxy in proxies:
        try:
            if proxy['type'] == "vless":
                name, server, port, uuid = proxy['name'], proxy['server'], proxy['port'], proxy['uuid']
                tls, network, flow = int(proxy.get('tls', 0)), proxy['network'], proxy.get('flow', "")
                grpc_serviceName = proxy.get('grpc-opts', {}).get('grpc-service-name', "")
                ws_path = proxy.get('ws-opts', {}).get('path', "")
                xhttp_path = proxy.get('xhttp-opts', {}).get('path', "")
                ws_headers_host = proxy.get('ws-opts', {}).get('headers', {}).get('host', "") or proxy.get('ws-opts', {}).get('headers', {}).get('Host', "")

                if not tls:
                    proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=none&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path if network != 'xhttp' else xhttp_path}#{name}"
                else:
                    sni = proxy.get('servername', "")
                    if 'reality-opts' in proxy:
                        reality_opts = proxy['reality-opts']
                        proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=reality&sni={sni}&fp={proxy.get('client-fingerprint', '')}&pbk={reality_opts.get('public-key', '')}&sid={reality_opts.get('short-id', '')}&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path if network != 'xhttp' else xhttp_path}#{name}"
                    else:
                        insecure = int(proxy.get('skip-cert-verify', 0))
                        proxy_url = f"vless://{uuid}@{server}:{port}?encryption=none&flow={flow}&security=tls&sni={sni}&fp={proxy.get('client-fingerprint', '')}&insecure={insecure}&type={network}&serviceName={grpc_serviceName}&host={ws_headers_host}&path={ws_path if network != 'xhttp' else xhttp_path}#{name}"
            
            elif proxy['type'] == "vmess":
                name, server, port, uuid, alterId = proxy['name'], proxy['server'], proxy['port'], proxy['uuid'], proxy['alterId']
                tls, sni, network = "tls" if int(proxy.get('tls', 0)) == 1 else "", proxy.get('servername', ""), proxy['network']
                
                type_map = {"tcp": "none", "ws": "none", "grpc": "gun", "h2": "none"}
                path_map = {"tcp": "", "ws": proxy.get('ws-opts', {}).get('path', ""), "grpc": proxy.get('grpc-opts', {}).get('serviceName', ""), "h2": proxy.get('h2-opts', {}).get('path', "")}
                host_map = {"tcp": "", "ws": proxy.get('ws-opts', {}).get('headers', {}).get('host', "") or proxy.get('ws-opts', {}).get('headers', {}).get('Host', ""), "grpc": "", "h2": ','.join(proxy.get('h2-opts', {}).get('host', []))}
                
                vmess_meta = {
                    "v": "2", "ps": name, "add": server, "port": port, "id": uuid, "aid": alterId,
                    "net": network, "type": type_map.get(network, "none"), "host": host_map.get(network, ""),
                    "path": path_map.get(network, ""), "tls": tls, "sni": sni, "alpn": ""
                }
                proxy_url = "vmess://" + base64.b64encode(json.dumps(vmess_meta).encode('utf-8')).decode('utf-8')
            
            elif proxy['type'] == "ss":
                name, server, port, password, cipher = proxy['name'], proxy['server'], proxy['port'], proxy['password'], proxy['cipher']
                ss_meta = base64.b64encode(f"{cipher}:{password}".encode('utf-8')).decode('utf-8')
                proxy_url = f"ss://{ss_meta}@{server}:{port}#{name}"
            
            elif proxy['type'] == "hysteria":
                name, server, port, protocol, insecure = proxy['name'], proxy['server'], proxy['port'], proxy.get('protocol', "udp"), int(proxy.get('skip-cert-verify', 0))
                peer, auth, alpn = proxy.get('sni', ""), proxy.get('auth-str', proxy.get('auth_str', "")), ','.join(proxy['alpn'])
                upmbps, downmbps, obfs = proxy.get('up', "11"), proxy.get('down', "55"), proxy.get('obfs', "")
                proxy_url = f"hysteria://{server}:{port}/?protocol={protocol}&insecure={insecure}&peer={peer}&auth={auth}&upmbps={upmbps}&downmbps={downmbps}&alpn={alpn}&obfs={obfs}#{name}"
            
            elif proxy['type'] == "hysteria2":
                name, server, port, auth, sni = proxy['name'], proxy['server'], proxy['port'], proxy['password'], proxy.get('sni', "")
                insecure = int(proxy.get('skip-cert-verify', 0))
                obfs, obfs_password = proxy.get('obfs', ""), proxy.get('obfs-password', "")
                obfs_param = f"&obfs={obfs}&obfs-password={obfs_password}" if obfs else ""
                proxy_url = f"hysteria2://{auth}@{server}:{port}/?sni={sni}&insecure={insecure}{obfs_param}#{name}"
            
            elif proxy['type'] == "tuic":
                name, server, port, uuid = proxy['name'], proxy['server'], proxy['port'], proxy['uuid']
                password, cc, udp_relay, sni = proxy.get('password', ""), proxy.get('congestion-controller', "bbr"), proxy.get('udp-relay-mode', "native"), proxy.get('sni', "")
                alpn = ','.join(proxy.get('alpn', []))
                
                # 修复核心：确保从 YAML 读取的布尔值被正确处理，转换为 1 或 0
                allowInsecure = 1 if proxy.get('skip-cert-verify') else 0
                reduce_rtt = 1 if proxy.get('reduce-rtt', False) else 0
                
                proxy_url = f"tuic://{uuid}:{password}@{server}:{port}?sni={sni}&alpn={alpn}&allow_insecure={allowInsecure}&congestion_control={cc}&udp_relay_mode={udp_relay}&reduce_rtt={reduce_rtt}#{name}"

            else:
                logging.error(f"处理 {proxy['name']} 时遇到问题: 不支持的协议: {proxy['type']}")
                continue

            proxy_urls.append(proxy_url)
        except Exception as e:
            logging.error(f"处理 {proxy['name']} 时遇到问题: {e}")
            continue
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(proxy_urls) + '\n')

def write_base64_file(output_file, proxy_urls_file):
    with open(proxy_urls_file, 'r', encoding='utf-8') as f:
        proxy_urls = f.read()
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(proxy_urls.encode('utf-8')).decode('utf-8'))

if __name__ == "__main__":
    servers_map = {}

    process_urls("./urls/clash_meta_urls.txt", process_clash_meta)
    process_urls("./urls/hysteria_urls.txt", process_hysteria)
    process_urls("./urls/hysteria2_urls.txt", process_hysteria2)
    process_urls("./urls/xray_urls.txt", process_xray)

    extracted_proxies = list(servers_map.values())
    
    write_clash_meta_profile("./templates/clash_meta.yaml", "./outputs/clash_meta.yaml", extracted_proxies)
    write_clash_meta_profile("./templates/clash_meta_warp.yaml", "./outputs/clash_meta_warp.yaml", extracted_proxies)

    write_proxy_urls_file("./outputs/proxy_urls.txt", extracted_proxies)
    write_base64_file("./outputs/base64.txt", "./outputs/proxy_urls.txt")
