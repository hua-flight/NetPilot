#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap 可视化扫描平台 - 后端
访问 http://192.168.5.2:5000
"""
import os
import json
import subprocess
import threading
import time
import uuid
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory

app = Flask(__name__)

# 扫描任务存储
scan_tasks = {}

# 扫描类型预设
SCAN_PRESETS = {
    "quick": {"name": "快速扫描", "args": "-sV -T4 --top-ports 100", "desc": "扫描最常用100个端口+服务识别"},
    "full": {"name": "全端口扫描", "args": "-sV -T4 -p-", "desc": "扫描全部65535个端口+服务识别"},
    "service": {"name": "服务深度识别", "args": "-sV -sC -T4 --top-ports 1000", "desc": "服务版本+脚本扫描"},
    "os": {"name": "操作系统检测", "args": "-O -sV -T4 --top-ports 100", "desc": "OS指纹识别+服务识别(需root)"},
    "vuln": {"name": "漏洞扫描", "args": "-sV --script=vuln,vulners -T4 --top-ports 100", "desc": "调用nmap漏洞脚本+CVE数据库扫描"},
    "ping": {"name": "存活探测", "args": "-sn -T4", "desc": "只探测主机是否存活，不扫端口"},
}


def parse_nmap_xml(xml_output):
    """解析nmap XML输出，提取结构化数据"""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_output)
    except Exception:
        return {"hosts": [], "stats": {}}

    hosts = []
    for host in root.findall("host"):
        # 状态
        status = host.find("status")
        state = status.get("state") if status is not None else "unknown"
        if state != "up":
            continue

        # 地址
        ipv4 = ""
        mac = ""
        vendor = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ipv4 = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        # 主机名
        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        # OS
        os_name = ""
        os_accuracy = 0
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "")
                os_accuracy = int(osmatch.get("accuracy", 0))

        # 端口
        ports = []
        open_ports = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                portid = int(port.get("portid", 0))
                protocol = port.get("protocol", "tcp")
                state_elem = port.find("state")
                port_state = state_elem.get("state") if state_elem is not None else "unknown"

                service_elem = port.find("service")
                service_name = service_elem.get("name", "") if service_elem is not None else ""
                service_product = service_elem.get("product", "") if service_elem is not None else ""
                service_version = service_elem.get("version", "") if service_elem is not None else ""

                port_info = {
                    "port": portid,
                    "protocol": protocol,
                    "state": port_state,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                }
                ports.append(port_info)
                if port_state == "open":
                    open_ports.append(port_info)

        # 推断设备类型
        device_type = infer_device_type(os_name, open_ports, vendor)

        # 解析漏洞信息 (nmap --script vuln/vulners)
        vulnerabilities = []
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "")
                if output.strip():
                    parsed = parse_vuln_script(sid, output, "")
                    vulnerabilities.extend(parsed)

        # 端口级别的漏洞脚本
        for port_elem in (ports_elem.findall("port") if ports_elem is not None else []):
            portid = int(port_elem.get("portid", 0))
            svc = port_elem.find("service")
            svc_name = svc.get("name","") if svc is not None else ""
            for script in port_elem.findall("script"):
                sid = script.get("id", "")
                output = script.get("output", "")
                if output.strip():
                    parsed = parse_vuln_script(sid, output, svc_name, portid)
                    vulnerabilities.extend(parsed)

        hosts.append({
            "ip": ipv4,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "os": os_name,
            "os_accuracy": os_accuracy,
            "state": state,
            "open_ports": open_ports,
            "all_ports": ports,
            "device_type": device_type,
            "vulnerabilities": vulnerabilities,
        })

    # 统计
    stats = {
        "total_hosts": len(hosts),
        "total_open_ports": sum(len(h["open_ports"]) for h in hosts),
        "scan_time": root.find("runstats/finished").get("elapsed", "0") if root.find("runstats/finished") is not None else "0",
    }

    return {"hosts": hosts, "stats": stats}


def parse_vuln_script(script_id, output, service="", port=0):
    """解析nmap漏洞脚本输出，提取CVE/CVSS/漏洞名"""
    import re
    results = []
    
    # 1. 解析vulners脚本输出：CVE-xxxx-xxxx  7.5 [CVSS:...]
    if script_id == "vulners":
        for line in output.split("\n"):
            line = line.strip()
            m = re.match(r"(CVE-\d{4}-\d+)\s+([\d.]+)", line)
            if m:
                cve = m.group(1)
                score = float(m.group(2))
                if score >= 7.0: severity = "高危"
                elif score >= 4.0: severity = "中危"
                else: severity = "低危"
                results.append({
                    "cve": cve, "severity": severity,
                    "name": f"CVE漏洞 {cve}", "desc": f"CVSS评分 {score}/10，{line[:150]}",
                    "port": port, "service": service
                })
        return results
    
    # 2. 解析其他vuln脚本（http-vuln-*, sslv2*, etc.）
    if "vuln" in script_id.lower() or "ssl" in script_id.lower() or "heartbleed" in script_id.lower():
        # 提取CVE
        cves = re.findall(r"CVE-\d{4}-\d+", output)
        first_line = output.strip().split("\n")[0] if output.strip() else script_id
        
        severity = "中危"
        # 检查是否有高危关键词
        for kw in ["critical", "high", "rce", "execute", "overflow", "heartbleed"]:
            if kw in output.lower():
                severity = "高危"
                break
        
        if cves:
            for cve in set(cves):
                results.append({
                    "cve": cve, "severity": severity,
                    "name": script_id.replace("-", " ").title(),
                    "desc": first_line[:200],
                    "port": port, "service": service
                })
        else:
            results.append({
                "cve": "", "severity": severity,
                "name": script_id.replace("-", " ").title(),
                "desc": first_line[:300],
                "port": port, "service": service
            })
    
    return results


def infer_device_type(os_name, open_ports, vendor):
    """根据OS、端口、厂商推断设备类型（含国产化/移动/IoT设备识别）"""
    open_port_nums = [p["port"] for p in open_ports]
    services = [p["service"] for p in open_ports]
    os_lower = (os_name or "").lower()
    vendor_lower = (vendor or "").lower()
    port_count = len(open_port_nums)

    # === 第一优先级：专用设备识别（多端口组合特征，避免误判）===

    # 1. NAS/私有云存储（极空间、群晖、威联通等）
    # 必须同时有SMB文件共享(139/445) + 至少一个NAS管理端口，不能只看单个端口
    has_smb = 139 in open_port_nums and 445 in open_port_nums
    nas_mgmt_ports = [5005, 5006, 5007, 6690, 9000, 9001, 9002, 9999, 11111, 32400, 8096]
    has_nas_mgmt = any(p in open_port_nums for p in nas_mgmt_ports)
    # 极空间特征：SMB + 5000管理端口 + 无53端口（路由器特征）
    if has_smb and has_nas_mgmt:
        return "NAS/私有云存储"
    # 极空间特殊情况：SMB + 5000 + 554(RTSP)，但没有53(DNS)
    if has_smb and 5000 in open_port_nums and 554 in open_port_nums and 53 not in open_port_nums:
        return "NAS/私有云存储"

    # 2. 监控设备/摄像头/NVR（不能只看554，要排除NAS）
    if 554 in open_port_nums and not has_smb and port_count <= 6:
        return "监控设备/摄像头或NVR"
    if 8000 in open_port_nums or 37777 in open_port_nums or 8554 in open_port_nums:
        return "监控设备/摄像头或NVR"

    # 3. 路由器（有DNS服务53端口是典型特征）
    if 53 in open_port_nums and (80 in open_port_nums or 443 in open_port_nums):
        return "网络设备/路由器"
    if 53 in open_port_nums and 22 in open_port_nums and port_count <= 6:
        return "网络设备/路由器"

    # 4. 防火墙/安全设备（必须有多个安全管理端口，不能只看22+443）
    fw_keywords = ["leadsec", "天融信", "topsec", "sangfor", "奇安信", "qianxin", "hillstone", "山石", "fortinet", "paloalto"]
    if any(k in vendor_lower for k in fw_keywords) and 22 in open_port_nums:
        return "安全设备/防火墙"
    # 防火墙特征：22 + 443 + 至少一个专用管理端口（8443/8444/9443），且端口数较少
    fw_mgmt_ports = [8443, 8444, 9443, 4433, 8888]
    if 22 in open_port_nums and any(p in open_port_nums for p in fw_mgmt_ports) and port_count <= 10:
        return "安全设备/防火墙"

    # 5. 交换机（SNMP/23 telnet是典型特征）
    netdev_ports = [23, 161, 162, 830, 8305, 2222]
    netdev_keywords = ["cisco", "huawei", "h3c", "tp-link", "tplink", "d-link", "dlink", "netgear", "锐捷", "ruijie", "中兴", "zte", "烽火", "fiberhome"]
    if any(k in vendor_lower for k in netdev_keywords) and 53 not in open_port_nums:
        return "网络设备/交换机"
    if 161 in open_port_nums or 162 in open_port_nums:  # SNMP
        return "网络设备/交换机"
    if 23 in open_port_nums and port_count <= 4 and 53 not in open_port_nums:
        return "网络设备/交换机"

    # 6. 移动设备（手机/平板）
    if 5555 in open_port_nums:  # Android ADB
        return "Android设备/手机平板"
    if 6207 in open_port_nums:  # iOS锁屏服务
        return "iOS设备/iPhone或iPad"
    if "android" in os_lower or "android" in vendor_lower:
        return "Android设备/手机平板"
    if "ios" in os_lower or "iphone" in os_lower or "ipad" in os_lower or "apple" in vendor_lower:
        return "iOS设备/iPhone或iPad"

    # 7. 打印机
    if 631 in open_port_nums or 9100 in open_port_nums or 515 in open_port_nums:
        return "网络打印机"

    # 8. UPS电源
    if 3493 in open_port_nums:
        return "UPS电源设备"

    # 9. IoT/智能家居
    iot_ports = [1883, 8883, 5683, 5684, 6668, 6669]
    if 1883 in open_port_nums or 8883 in open_port_nums:  # MQTT
        return "IoT设备/MQTT网关"
    if 5683 in open_port_nums or 5684 in open_port_nums:  # CoAP
        return "IoT设备/传感器"
    iot_keywords = ["xiaomi", "小米", "mi", "aqara", "绿米", "tuya", "涂鸦", "esp", "arduino", "raspberry", "树莓派"]
    if any(k in vendor_lower for k in iot_keywords):
        return "IoT/智能家居设备"

    # 10. 虚拟化/云平台
    if 8006 in open_port_nums or 10443 in open_port_nums:
        return "虚拟化平台/PVE或ESXi"
    if 5988 in open_port_nums or 5989 in open_port_nums:  # WBEM
        return "虚拟化/云平台"

    # === 第二优先级：国产化操作系统识别 ===
    if "kylin" in os_lower or "银河麒麟" in os_name or "kylin" in vendor_lower:
        return "国产化服务器/银河麒麟"
    if "uos" in os_lower or "uniontech" in os_lower or "统信" in os_name:
        return "国产化终端/统信UOS"
    if "openeuler" in os_lower or "欧拉" in os_name:
        return "国产化服务器/openEuler"
    if "loongson" in os_lower or "loongarch" in os_lower or "龙芯" in os_name:
        return "国产化服务器/龙芯平台"
    if "phytium" in os_lower or "飞腾" in os_name:
        return "国产化服务器/飞腾平台"
    if "kunpeng" in os_lower or "鲲鹏" in os_name:
        return "国产化服务器/华为鲲鹏"
    if "deepin" in os_lower or "深度" in os_name:
        return "国产化系统/Deepin桌面"
    if "neokylin" in os_lower or "中标" in os_name:
        return "国产化服务器/中标麒麟"
    if "redflag" in os_lower or "红旗" in os_name:
        return "国产化系统/红旗Linux"

    # === 第三优先级：通用服务器判断 ===
    # 注意：445/139不能单独判断Windows，NAS也会开SMB
    if 445 in open_port_nums and 139 in open_port_nums and 3389 in open_port_nums:
        return "Windows主机"
    if 3389 in open_port_nums and 5985 in open_port_nums:
        return "Windows服务器"
    # Linux服务器：22 + 至少一个Web/服务端口，且不是路由器特征（无53）
    if 22 in open_port_nums and (80 in open_port_nums or 443 in open_port_nums or 5000 in open_port_nums or 8080 in open_port_nums) and 53 not in open_port_nums:
        return "Linux服务器"
    if any(s in services for s in ["http", "https"]) and any(p in open_port_nums for p in [80, 443, 8080, 8443]) and 22 in open_port_nums and 53 not in open_port_nums:
        return "Web服务器/Linux"
    if 3389 in open_port_nums:
        return "Windows远程桌面"
    if 5900 in open_port_nums:
        return "VNC远程桌面"
    if 3306 in open_port_nums:
        return "数据库服务器/MySQL"
    if 6379 in open_port_nums:
        return "Redis服务器"
    if 1521 in open_port_nums:
        return "数据库服务器/Oracle"
    if 5432 in open_port_nums:
        return "数据库服务器/PostgreSQL"
    if 27017 in open_port_nums:
        return "数据库服务器/MongoDB"
    if 9200 in open_port_nums:
        return "搜索引擎/Elasticsearch"
    if 8848 in open_port_nums:
        return "微服务/Nacos"
    if 3000 in open_port_nums or 9090 in open_port_nums:
        return "监控/Prometheus或Grafana"

    # === 第四优先级：OS名称匹配 ===
    if "windows" in os_lower:
        return "Windows主机"
    if "linux" in os_lower:
        return "Linux主机"
    if "mac" in os_lower or "darwin" in os_lower:
        return "Mac设备"
    if "freebsd" in os_lower or "bsd" in os_lower:
        return "BSD系统设备"

    if not open_ports:
        return "未知设备(无开放端口)"
    return "未知设备"


def run_scan(task_id, target, preset, custom_ports, speed, extra_args):
    """后台执行nmap扫描"""
    task = scan_tasks[task_id]
    task["status"] = "running"
    task["start_time"] = time.time()

    try:
        # 构建命令
        preset_info = SCAN_PRESETS.get(preset, SCAN_PRESETS["quick"])
        args = preset_info["args"]

        if custom_ports:
            args = args.replace("--top-ports 100", f"-p {custom_ports}")
            args = args.replace("--top-ports 1000", f"-p {custom_ports}")

        if speed:
            args = args.replace("-T4", f"-T{speed}")

        if extra_args:
            args += f" {extra_args}"

        # 需要root的扫描类型
        need_root = preset in ["os", "vuln"] or "-sS" in args or "-O" in args

        cmd = f"nmap {args} -oX - {target}"
        if need_root:
            cmd = f"sudo nmap {args} -oX - {target}"

        task["command"] = cmd

        # 执行
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )

        # 实时读取输出（XML是最后才完整输出，这里只记录进度）
        stdout_lines = []
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if line:
                stdout_lines.append(line)
                task["progress"] = min(95, task.get("progress", 0) + 0.1)

        remaining = proc.stdout.read()
        if remaining:
            stdout_lines.append(remaining)

        xml_output = "".join(stdout_lines)
        stderr = proc.stderr.read()

        # 解析结果
        result = parse_nmap_xml(xml_output)
        result["raw_xml"] = xml_output[:50000]  # 限制大小
        result["stderr"] = stderr[-2000:] if stderr else ""

        task["result"] = result
        task["status"] = "completed"
        task["progress"] = 100
        task["end_time"] = time.time()

    except Exception as e:
        task["status"] = "error"
        task["error"] = str(e)
        task["end_time"] = time.time()


@app.route("/")
def index():
    return render_template("index.html", presets=SCAN_PRESETS)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json
    target = data.get("target", "").strip()
    preset = data.get("preset", "quick")
    custom_ports = data.get("ports", "").strip()
    speed = data.get("speed", "4")
    extra_args = data.get("extra_args", "").strip()

    if not target:
        return jsonify({"error": "请输入目标IP或网段"}), 400

    task_id = str(uuid.uuid4())[:8]
    scan_tasks[task_id] = {
        "id": task_id,
        "target": target,
        "preset": preset,
        "status": "pending",
        "progress": 0,
        "result": None,
        "command": "",
    }

    t = threading.Thread(target=run_scan, args=(task_id, target, preset, custom_ports, speed, extra_args))
    t.daemon = True
    t.start()

    return jsonify({"task_id": task_id})


@app.route("/api/status/<task_id>")
def scan_status(task_id):
    task = scan_tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404
    return jsonify({
        "status": task["status"],
        "progress": round(task.get("progress", 0), 1),
        "command": task.get("command", ""),
        "elapsed": round(time.time() - task.get("start_time", time.time()), 1) if task.get("start_time") else 0,
    })


@app.route("/api/result/<task_id>")
def scan_result(task_id):
    task = scan_tasks.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404
    if task["status"] != "completed":
        return jsonify({"error": "扫描未完成", "status": task["status"]}), 400
    return jsonify(task["result"])


@app.route("/api/export/<task_id>/<fmt>")
def export_result(task_id, fmt):
    task = scan_tasks.get(task_id)
    if not task or not task.get("result"):
        return jsonify({"error": "无结果可导出"}), 404

    result = task["result"]
    filename = f"nmap_scan_{task_id}"

    if fmt == "json":
        filepath = f"/tmp/{filename}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return send_file(filepath, as_attachment=True, download_name=f"{filename}.json")

    elif fmt == "html":
        filepath = f"/tmp/{filename}.html"
        html = generate_html_report(result, task["target"])
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return send_file(filepath, as_attachment=True, download_name=f"{filename}.html")

    elif fmt == "vuln":
        filepath = f"/tmp/{filename}_vuln.html"
        html = generate_vuln_report(result, task["target"])
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return send_file(filepath, as_attachment=True, download_name=f"{filename}_漏洞报表.html")

    return jsonify({"error": "不支持的格式"}), 400


def generate_html_report(result, target):
    """生成HTML报告"""
    hosts = result.get("hosts", [])
    stats = result.get("stats", {})
    rows = ""
    for h in hosts:
        ports_str = ", ".join([f"{p['port']}/{p['service']}" for p in h["open_ports"]]) or "无"
        rows += f"""<tr>
            <td>{h['ip']}</td><td>{h['hostname'] or '-'}</td>
            <td>{h['device_type']}</td><td>{h['os'] or '-'}</td>
            <td>{ports_str}</td>
        </tr>"""

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Nmap扫描报告 - {target}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap');
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Microsoft YaHei',sans-serif; background:#0a0e17; color:#e0e0e0; padding:20px; }}
.header {{ background:linear-gradient(135deg,#0a1628,#0d2137); border:1px solid #00ff88; border-radius:10px; padding:20px 25px; margin-bottom:20px; box-shadow:0 0 30px rgba(0,255,136,0.15); }}
.header h2 {{ color:#00ff88; font-family:'Orbitron',monospace; letter-spacing:2px; text-shadow:0 0 10px rgba(0,255,136,0.5); }}
.header p {{ color:#8899aa; margin-top:8px; font-size:13px; }}
.stats {{ display:flex; gap:15px; margin-bottom:20px; }}
.stat-box {{ flex:1; padding:18px; border-radius:10px; text-align:center; border:1px solid; }}
.stat-box h3 {{ font-size:28px; font-family:'Orbitron',monospace; }}
.stat-hosts {{ background:rgba(0,150,255,0.1); border-color:#0096ff; }}
.stat-hosts h3 {{ color:#0096ff; text-shadow:0 0 15px rgba(0,150,255,0.5); }}
.stat-ports {{ background:rgba(0,255,136,0.1); border-color:#00ff88; }}
.stat-ports h3 {{ color:#00ff88; text-shadow:0 0 15px rgba(0,255,136,0.5); }}
.stat-time {{ background:rgba(160,0,255,0.1); border-color:#a000ff; }}
.stat-time h3 {{ color:#a000ff; text-shadow:0 0 15px rgba(160,0,255,0.5); }}
table {{ border-collapse:collapse; width:100%; background:rgba(13,33,55,0.6); border-radius:8px; overflow:hidden; }}
th {{ background:rgba(0,255,136,0.15); color:#00ff88; padding:12px 10px; font-size:13px; text-align:left; white-space:nowrap; border-bottom:1px solid #00ff88; font-weight:600; }}
td {{ padding:10px; font-size:12px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; }}
tr:hover {{ background:rgba(0,255,136,0.05); }}
tr:nth-child(even) {{ background:rgba(255,255,255,0.02); }}
</style></head><body>
<div class="header"><h2>🛡️ Nmap 资产扫描报告</h2>
<p>扫描目标: {target} | 生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}</p></div>
<div class="stats">
<div class="stat-box stat-hosts"><h3>{stats.get('total_hosts',0)}</h3><span style="color:#8899aa;font-size:13px">存活主机</span></div>
<div class="stat-box stat-ports"><h3>{stats.get('total_open_ports',0)}</h3><span style="color:#8899aa;font-size:13px">开放端口</span></div>
<div class="stat-box stat-time"><h3>{stats.get('scan_time','0')}s</h3><span style="color:#8899aa;font-size:13px">扫描耗时</span></div>
</div>
<table><tr><th>IP地址</th><th>主机名</th><th>设备类型</th><th>操作系统</th><th>开放端口</th></tr>
{rows}</table></body></html>"""


def generate_vuln_report(result, target):
    """生成漏洞扫描台账报表（类似安全运维报表格式）"""
    hosts = result.get("hosts", [])
    now = time.strftime("%Y-%m-%d %H:%M:%S")

    # 收集所有漏洞
    vuln_rows = []
    seq = 1
    for h in hosts:
        vuls = h.get("vulnerabilities", [])
        if not vuls:
            continue
        for v in vuls:
            # 资产类型
            asset_type = h.get("device_type", "服务器")
            # 报警类型
            alarm_type = "nmap漏洞扫描"
            # 报警级别
            level = v.get("severity", "中危")
            # 报警描述
            alarm_desc = f"发现设备{h['ip']}存在{v.get('name','漏洞')}，漏洞编号:{v.get('cve','未知')}"
            # CVE ID
            cve_id = v.get("cve", "")
            # CNVD ID (从CVE映射)
            cnvd_id = ""
            if cve_id:
                cnvd_id = f"CNVD-{cve_id.replace('CVE-','')}"
            # 漏洞名称
            vuln_name = v.get("name", "未知漏洞")
            # 漏洞描述
            vuln_desc = v.get("desc", "")
            # 修复建议
            fix_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""
            fix_advice = "请升级受影响组件到最新版本，或联系厂商获取补丁"
            if cve_id:
                fix_advice = f"参考NVD详情: {fix_url}"

            vuln_rows.append({
                "seq": seq,
                "ip": h["ip"],
                "asset_type": asset_type,
                "alarm_type": alarm_type,
                "level": level,
                "alarm_desc": alarm_desc,
                "cve": cve_id,
                "cnvd": cnvd_id,
                "vuln_name": vuln_name,
                "vuln_desc": vuln_desc,
                "fix": fix_advice,
                "count": 1,
                "remark": "",
                "time": now,
            })
            seq += 1

    # 生成HTML表格
    rows_html = ""
    for r in vuln_rows:
        level_color = "#ff4444" if r["level"] == "高危" else "#ffa500" if r["level"] == "中危" else "#00ff88"
        rows_html += f"""<tr>
            <td>{r['seq']}</td><td>{r['ip']}</td><td>{r['asset_type']}</td>
            <td>{r['alarm_type']}</td><td style="color:{level_color};font-weight:bold">{r['level']}</td>
            <td>{r['alarm_desc']}</td><td>{r['cve']}</td><td>{r['cnvd']}</td>
            <td>{r['vuln_name']}</td><td>{r['vuln_desc']}</td>
            <td>{r['fix']}</td><td>{r['count']}</td><td>{r['remark']}</td><td>{r['time']}</td>
        </tr>"""

    # 统计
    high = sum(1 for r in vuln_rows if r["level"] == "高危")
    mid = sum(1 for r in vuln_rows if r["level"] == "中危")
    low = sum(1 for r in vuln_rows if r["level"] == "低危")

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>漏洞扫描台账报表 - {target}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap');
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Microsoft YaHei',sans-serif; background:#0a0e17; color:#e0e0e0; padding:20px; }}
.header {{ background:linear-gradient(135deg,#0a1628,#0d2137); border:1px solid #00ff88; border-radius:10px; padding:20px 25px; margin-bottom:20px; box-shadow:0 0 30px rgba(0,255,136,0.15); }}
.header h2 {{ color:#00ff88; font-family:'Orbitron',monospace; letter-spacing:2px; text-shadow:0 0 10px rgba(0,255,136,0.5); }}
.header p {{ color:#8899aa; margin-top:8px; font-size:13px; }}
.stats {{ display:flex; gap:15px; margin-bottom:20px; }}
.stat-box {{ flex:1; padding:18px; border-radius:10px; text-align:center; border:1px solid; }}
.stat-box h3 {{ font-size:28px; font-family:'Orbitron',monospace; }}
.stat-high {{ background:rgba(255,68,68,0.1); border-color:#ff4444; }}
.stat-high h3 {{ color:#ff4444; text-shadow:0 0 15px rgba(255,68,68,0.5); }}
.stat-mid {{ background:rgba(255,165,0,0.1); border-color:#ffa500; }}
.stat-mid h3 {{ color:#ffa500; text-shadow:0 0 15px rgba(255,165,0,0.5); }}
.stat-low {{ background:rgba(0,255,136,0.1); border-color:#00ff88; }}
.stat-low h3 {{ color:#00ff88; text-shadow:0 0 15px rgba(0,255,136,0.5); }}
table {{ border-collapse:collapse; width:100%; background:rgba(13,33,55,0.6); border-radius:8px; overflow:hidden; }}
th {{ background:rgba(0,255,136,0.15); color:#00ff88; padding:10px 8px; font-size:12px; text-align:left; white-space:nowrap; border-bottom:1px solid #00ff88; font-weight:600; }}
td {{ padding:8px; font-size:12px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; }}
tr:hover {{ background:rgba(0,255,136,0.05); }}
tr:nth-child(even) {{ background:rgba(255,255,255,0.02); }}
a {{ color:#00ff88; text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
</style></head><body>
<div class="header"><h2>🛡️ 漏洞扫描台账报表</h2>
<p>扫描目标: {target} | 生成时间: {now} | 共发现 {len(vuln_rows)} 个漏洞</p></div>
<div class="stats">
<div class="stat-box stat-high"><h3>{high}</h3><span style="color:#8899aa;font-size:13px">高危</span></div>
<div class="stat-box stat-mid"><h3>{mid}</h3><span style="color:#8899aa;font-size:13px">中危</span></div>
<div class="stat-box stat-low"><h3>{low}</h3><span style="color:#8899aa;font-size:13px">低危</span></div>
</div>
<table>
<tr><th>序号</th><th>IP地址</th><th>资产类型</th><th>报警类型</th><th>报警级别</th>
<th>报警描述</th><th>CVE ID</th><th>CNVD ID</th><th>漏洞名称</th>
<th>漏洞描述</th><th>修复建议</th><th>次数</th><th>备注</th><th>报警时间</th></tr>
{rows_html}</table></body></html>"""


# ============================================================
# 设备台账管理 + AI策略下发模块
# ============================================================
import requests as http_req
import paramiko

DEVICES_FILE = "/home/lxh/nmap-web/data/devices.json"
LOGS_FILE = "/home/lxh/nmap-web/data/operation_logs.json"
LLM_CONFIG_FILE = "/home/lxh/nmap-web/data/llm_config.json"
# 默认DeepSeek API配置（可在Web端修改）
DEFAULT_LLM_CONFIG = {
    "api": "https://api.deepseek.com/v1/chat/completions",
    "model": "deepseek-flash",
    "api_key": ""
}

os.makedirs(os.path.dirname(DEVICES_FILE), exist_ok=True)


def load_json(filepath, default):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(filepath, data):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_llm_config():
    """获取LLM配置，优先使用用户自定义配置，默认使用DeepSeek"""
    config = load_json(LLM_CONFIG_FILE, DEFAULT_LLM_CONFIG)
    # 确保所有字段都有值
    for k, v in DEFAULT_LLM_CONFIG.items():
        if k not in config or not config[k]:
            config[k] = v
    return config


# ---------- 设备管理 ----------

@app.route("/api/devices", methods=["GET"])
def list_devices():
    devices = load_json(DEVICES_FILE, [])
    # 不返回密码
    safe = []
    for d in devices:
        d2 = {k: v for k, v in d.items() if k != "password"}
        d2["has_password"] = bool(d.get("password"))
        safe.append(d2)
    return jsonify(safe)


@app.route("/api/devices", methods=["POST"])
def add_device():
    data = request.json
    devices = load_json(DEVICES_FILE, [])
    data["id"] = str(uuid.uuid4())[:8]
    devices.append(data)
    save_json(DEVICES_FILE, devices)
    return jsonify({"ok": True, "id": data["id"]})


@app.route("/api/devices/<device_id>", methods=["PUT"])
def update_device(device_id):
    data = request.json
    devices = load_json(DEVICES_FILE, [])
    for i, d in enumerate(devices):
        if d.get("id") == device_id:
            data["id"] = device_id
            devices[i] = data
            save_json(DEVICES_FILE, devices)
            return jsonify({"ok": True})
    return jsonify({"error": "设备不存在"}), 404


@app.route("/api/devices/<device_id>", methods=["DELETE"])
def delete_device(device_id):
    devices = load_json(DEVICES_FILE, [])
    devices = [d for d in devices if d.get("id") != device_id]
    save_json(DEVICES_FILE, devices)
    return jsonify({"ok": True})


@app.route("/api/devices/<device_id>/test", methods=["POST"])
def test_device(device_id):
    """测试SSH连接"""
    devices = load_json(DEVICES_FILE, [])
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "设备不存在"}), 404
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=dev["ip"], port=int(dev.get("ssh_port", 22)),
            username=dev["username"], password=dev["password"],
            timeout=8,
        )
        stdin, stdout, stderr = client.exec_command("display version" if dev.get("vendor") in ["h3c", "huawai"] else "show version", timeout=8)
        output = stdout.read().decode("utf-8", errors="replace")[:500]
        client.close()
        return jsonify({"ok": True, "output": output})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ---------- AI策略生成 ----------

VENDOR_GUIDE = {
    "leadsec": """网御星云安全网关Power-V防火墙（真实生产配置格式）。严格按照以下从真实设备导出的批处理格式输出，所有命令一行一条，不要加system-view，不要加多余解释。

【真实配置格式（从生产设备导出，直接批处理导入）】
# 接口配置
interface set phy if eth0 ip 10.1.5.254 netmask 255.255.255.0 active on admin on ping on traceroute on workmode route mtu 1500
interface set phy if eth1 ip none netmask none active on admin off ping off traceroute off workmode trans mtu 1500
interface set brg if brg0 ip 10.1.4.254 netmask 255.255.255.0 active off admin on ping on traceroute on interface_list vlan_id 0
interface add alias bind_if eth13 active on admin off ping off traceroute on ip 111.77.158.240 netmask 255.255.255.0 alias_id 1

# 静态路由配置
route troute add destip 0.0.0.0/0.0.0.0 tablename main metric 20 nexthop 111.77.158.1 dev eth13 weight 1 detectname ""
route troute add destip 172.16.10.0/255.255.255.0 tablename main metric 4 nexthop 10.10.10.2 dev eth14 weight 1 detectname ""

# 管理IP设置
admhost add ip 10.1.5.0 netmask 255.255.255.0 comment ""

# 地址对象定义
address add name "172_16_10_10" ip "172.16.10.10/255.255.255.255" core_assets "0" comment ""
address add name "测试网段" ip "172.16.10.10-172.16.10.20" core_assets "0" comment ""
addrgrp add name "服务器组" member "server1,server2,server3" comment ""

# 服务对象定义
service add name "web服务" protocol tcp sp 0-65535 dp 80-80 protocol tcp sp 0-65535 dp 443-443 protocol udp sp 0-65535 dp 53-53 comment ""
service add name "高危端口" protocol tcp sp 0-65535 dp 135-139 protocol tcp sp 0-65535 dp 445-445 comment ""

# 安全策略规则
rule add type permit id 1 name "允许内网上网" sa 172.16.10.0/255.255.255.0 da any izone any ozone any service any time any log on active on comment ""
rule add type deny id 2 name "禁止渗透主机" sa "渗透组" da any izone any ozone any service any time any log on active on comment ""

# NAT源地址转换
rule add type nat name "源NAT" id 10 sa 172.16.10.0/255.255.255.0 sat 111.77.158.239 satt sdahash da any oif eth13 service any active on comment ""

# NAT目的地址转换（端口映射）
rule add type portmap name "Web映射" id 20 sa any sat 10.10.10.1 pa 111.77.158.239 ia 172.16.10.10 oif any iif any ps 80 is 80 active on comment ""

# 一对一地址映射
rule add type ipmap name "VIP映射" id 30 sa any sat 10.10.10.1 pa 111.77.158.239 ia 172.16.10.13 oif any iif any active on comment ""

【关键参数说明】
- interface set phy if：物理接口配置
  - ip：接口IP（none表示无IP）
  - netmask：子网掩码
  - active on/off：接口启用/关闭
  - admin on/off：管理权限
  - workmode route/trans：路由模式/透明模式
- route troute add：静态路由
  - destip：目标网段/掩码（格式：目标IP/掩码，如0.0.0.0/0.0.0.0）
  - nexthop：下一跳
  - dev：出接口
  - metric：优先级
- rule add type：安全规则
  - permit/deny：允许/拒绝
  - portmap：目的NAT（端口映射）
  - nat：源NAT
  - ipmap：一对一NAT
  - sa：源地址（IP/掩码、地址组名、any）
  - da：目的地址
  - service：服务名或any
  - active on：生效
  - log on：记录日志
- address add name：定义地址对象
- service add name：定义服务对象
- admhost add：允许管理的IP

【跨版本说明】
网御星云Power-V所有版本（V1.x/V2.x/V3.x/V5.x）的命令行批处理格式完全一致，以上格式可直接导入。
不需要system-view，不需要进入视图，所有命令一行一条直接执行。

【示例】
需求：允许192.168.1.0/24网段访问互联网并做源NAT
输出：
address add name "内网网段" ip "192.168.1.0/255.255.255.0" core_assets "0" comment ""
rule add type permit name "允许内网" id 1 sa "内网网段" da any izone any ozone any service any time any log on active on comment ""
rule add type nat name "源NAT" id 2 sa "内网网段" sat 202.101.244.16 satt sdahash da any oif eth13 service any active on comment ""

需求：把外网80端口映射到内网192.168.1.100的8080端口
输出：
address add name "Web服务器" ip "192.168.1.100/255.255.255.255" core_assets "0" comment ""
rule add type portmap name "Web映射" id 10 sa any sat 202.101.244.16 pa 202.101.244.16 ia "Web服务器" oif any iif any ps 80 is 8080 active on comment ""

严格按以上真实生产格式输出，不要用华为的security-policy，不要用Cisco的ip nat inside。""",
    "h3c": """H3C Comware系统，严格按以下语法：
【视图切换】
- system-view：从用户视图进入系统视图
- quit：退回上一级
- return：直接回到用户视图（Ctrl+Z）
【查看命令】（用户视图<H3C>或系统视图[H3C]直接敲）
- display version：查看版本
- display current-configuration：查看全部运行配置
- display current-configuration | include XXX：过滤关键字
- display saved-configuration：查看flash中保存的配置
- display ip interface brief：查看所有接口IP摘要
- display interface brief：查看接口状态摘要
- display vlan：查看VLAN信息
- display vlan brief：VLAN摘要
- display port：查看端口VLAN分配
- display cpu-usage：CPU利用率
- display memory：内存利用率
- display ip routing-table：路由表
- display arp：ARP表
- display mac-address：MAC地址表
- display logbuffer：系统日志
- display device：单板/设备状态
- display stp：生成树状态
- display ospf peer：OSPF邻居
- display bgp peer：BGP邻居
【系统配置】（system-view下）
- sysname SW1：改设备名
- undo info-center enable：关闭控制台日志提示
- vlan 10：创建VLAN 10
- vlan 10 20 30：批量创建VLAN
【接口配置】
- interface GigabitEthernet1/0/1：进入接口（H3C盒式交换机）
- interface GigabitEthernet1/0/1:1：子接口
- port link-type access：设为access口
- port access vlan 10：access口加入VLAN 10
- port link-type trunk：设为trunk口
- port trunk permit vlan 10 20：trunk放行VLAN
- port trunk pvid vlan 10：trunk缺省VLAN
- description Uplink_to_Core：接口描述
- undo shutdown：开启接口
【VLAN三层接口】
- interface Vlan-interface 10：进入VLAN三层接口（注意：是Vlan-interface不是Vlanif）
- ip address 192.168.10.1 24：配置IP
【VLAN视图批量加端口】
- vlan 10
- port GigabitEthernet1/0/1 to GigabitEthernet1/0/20：批量加入VLAN
【ACL配置】
- acl number 2000：基本ACL（2000-2999）
- acl number 3000：高级ACL（3000-3999）
- rule 5 deny ip source 192.168.1.0 0.0.0.255：拒绝源网段
- rule 10 permit ip source 192.168.1.10 0 destination any：允许单IP
- rule 15 deny tcp source 192.168.1.0 0.0.0.255 destination-port eq 22：封禁SSH
- interface GigabitEthernet1/0/1下：packet-filter 3000 inbound：入方向应用ACL（注意：是packet-filter不是traffic-filter）
【路由】
- ip route-static 0.0.0.0 0 192.168.1.254：默认路由
- ip route-static 192.168.2.0 24 192.168.1.1：静态路由
【保存】
- 用户视图下输入save force保存到flash（有些版本需要force参数）
【与华为的关键差异】
- 接口编号：H3C是GigabitEthernet1/0/1（不是华为的0/0/1）
- VLAN三层接口：H3C用Vlan-interface，华为用Vlanif
- ACL应用：H3C用packet-filter，华为用traffic-filter
- 保存：H3C用save force，华为用save
- 批量VLAN加端口：H3C在VLAN视图下用port命令，华为在接口下用port default vlan
【示例】
需求：查看接口状态
输出：display ip interface brief
需求：创建VLAN 20并把G1/0/2加入
输出：
system-view
vlan 20
port GigabitEthernet1/0/2
quit
save force
严格使用以上语法，不要用华为的traffic-filter或Vlanif，不要用Cisco的configure terminal。""",
    "huawei": """华为VRP系统（eNSP模拟器），严格按以下语法：
【视图切换】
- system-view：从用户视图进入系统视图
- quit：退回上一级
- return：直接回到用户视图（Ctrl+Z）
【查看命令】（用户视图<Huawei>或系统视图[Huawei]直接敲）
- display version：查看版本
- display current-configuration：查看全部运行配置
- display current-configuration | include XXX：过滤关键字
- display saved-configuration：查看flash中保存的配置
- display ip interface brief：查看所有接口IP摘要
- display interface brief：查看接口状态摘要
- display vlan：查看VLAN信息
- display vlan summary：VLAN摘要
- display port vlan：查看端口VLAN分配
- display cpu-usage：CPU利用率
- display memory-usage：内存利用率
- display ip routing-table：路由表
- display ip routing-table protocol static：静态路由
- display arp：ARP表
- display mac-address：MAC地址表
- display logbuffer：系统日志
- display alarm all：活动告警
- display device：单板/设备状态
- display stp：生成树状态
- display ospf peer：OSPF邻居
- display bgp peer：BGP邻居
【系统配置】（system-view下）
- sysname SW1：改设备名
- undo info-center enable：关闭控制台日志提示
- vlan 10：创建VLAN 10
- vlan batch 10 20 30：批量创建VLAN
- interface Vlanif 10：进入VLAN三层接口
- ip address 192.168.10.1 24：配置IP
【接口配置】
- interface GigabitEthernet0/0/1：进入接口（盒式交换机）
- interface GigabitEthernet1/0/1：进入接口（框式/模块化交换机）
- port link-type access：设为access口
- port default vlan 10：access口加入VLAN 10
- port link-type trunk：设为trunk口
- port trunk allow-pass vlan 10 20：trunk放行VLAN
- port trunk pvid vlan 10：trunk缺省VLAN
- description Uplink_to_Core：接口描述
- undo shutdown：开启接口（默认开启）
【ACL配置】
- acl number 2000：基本ACL（2000-2999，匹配源IP）
- acl number 3000：高级ACL（3000-3999，匹配五元组）
- rule 5 deny ip source 192.168.1.0 0.0.0.255：拒绝源网段
- rule 10 permit ip source 192.168.1.10 0 destination any：允许单IP
- rule 15 deny tcp source 192.168.1.0 0.0.0.255 destination-port eq 22：封禁SSH
- interface GigabitEthernet0/0/1下：traffic-filter inbound acl 3000：入方向应用ACL
【路由】
- ip route-static 0.0.0.0 0 192.168.1.254：默认路由
- ip route-static 192.168.2.0 24 192.168.1.1：静态路由
【保存】
- 用户视图下输入save，按Y确认保存到flash
【版本差异注意】
- 盒式交换机（S2700/S5700/S5720）：接口编号GigabitEthernet0/0/X
- 框式交换机（S7700/S9700/S12700）：接口编号GigabitEthernet槽位/子卡号/端口，如1/0/1
- V200R005之前：模块化交换机ACL需要classifier/behavior/traffic-policy五步配置
- V200R005及以后：直接traffic-filter调用ACL即可
【示例】
需求：查看接口状态
输出：display ip interface brief
需求：创建VLAN 20并把G0/0/2加入
输出：
system-view
vlan 20
quit
interface GigabitEthernet0/0/2
port link-type access
port default vlan 20
quit
save
严格使用以上语法，不要用Cisco的configure terminal，不要用H3C的packet-filter。

【路由器特有命令（AR系列：AR150/AR200/AR1200/AR2200/AR3200）】
--- 接口配置 ---
- interface GigabitEthernet0/0/0：进入GE接口
- interface Serial0/0/0：进入串口（PPP/HDLC）
- link-protocol ppp：串口封装PPP
- link-protocol hdlc：串口封装HDLC
- ip address ppp-negotiate：PPP自动获取IP
- dialer-rule：拨号规则
- interface Dialer1：进入拨号接口
- link-protocol ppp
- ip address ppp-negotiate
- pppoe-client dial-bundle-number 1：PPPoE拨号
- dialer-user user password：PPPoE账号密码
--- NAT ---
- acl number 2000：定义NAT感兴趣流
- rule 5 permit source 192.168.1.0 0.0.0.255
- interface GigabitEthernet0/0/0（外网口）下：
  - nat outbound 2000：Easy IP（直接用接口IP）
  - nat outbound 2000 address-group 1：NAT地址池
  - nat server protocol tcp global current-interface 80 inside 192.168.1.100 www：端口映射
- display nat session：查看NAT会话
- display nat server：查看NAT服务器映射
--- 路由协议 ---
- OSPF：
  - ospf 1 router-id 1.1.1.1
  - area 0
  - network 192.168.1.0 0.0.0.255
  - display ospf peer：查看OSPF邻居
  - display ospf lsdb：链路状态数据库
- BGP：
  - bgp 65001
  - peer 1.1.1.2 as-number 65002
  - ipv4-family unicast
  - peer 1.1.1.2 enable
  - display bgp peer：查看BGP邻居
  - display bgp routing-table：BGP路由表
- RIP：
  - rip 1
  - version 2
  - network 192.168.1.0
  - display rip 1 route：查看RIP路由
--- DHCP ---
- dhcp enable：全局开启DHCP
- ip pool vlan10：创建地址池
  - network 192.168.10.0 mask 24
  - gateway-list 192.168.10.1
  - dns-list 114.114.114.114
- interface Vlanif10下：dhcp select global
--- 静态路由 ---
- ip route-static 0.0.0.0 0 192.168.1.254：默认路由
- ip route-static 192.168.2.0 24 192.168.1.1 preference 70：浮动静态路由
--- 查看命令（路由器特有） ---
- display nat session：NAT会话表
- display ospf peer brief：OSPF邻居摘要
- display bgp peer brief：BGP邻居摘要
- display interface Serial0/0/0：串口状态
- display dialer：拨号接口状态
- display dhcp pool：DHCP地址池
- display dhcp server lease：DHCP租约
【路由器示例】
需求：配置PPPoE拨号上网并做NAT
输出：
system-view
acl number 2000
 rule 5 permit source 192.168.1.0 0.0.0.255
quit
interface Dialer1
 link-protocol ppp
 ip address ppp-negotiate
 pppoe-client dial-bundle-number 1
 nat outbound 2000
quit
interface GigabitEthernet0/0/0
 pppoe-client dial-bundle-number 1
quit
ip route-static 0.0.0.0 0 Dialer1
save""",
    "cisco": "Cisco IOS系统。进入配置模式用'configure terminal'，ACL用'access-list'，接口下用'ip access-group'。保存用'write memory'。",
    "linux": """Linux系统设备（服务器/路由器/NAS），直接执行shell命令。

【不同类型Linux设备的差异】
1. **标准Linux服务器（Ubuntu/CentOS/Debian）**：
   - 服务管理：systemctl start/stop/restart 服务名
   - 防火墙：iptables -A INPUT ...，保存用 service iptables save 或 iptables-save > /etc/sysconfig/iptables
   - 网络配置：/etc/network/interfaces 或 /etc/netplan/*.yaml
   - 不需要save命令，配置直接生效

2. **OpenWrt/Kwrt路由器**：
   - 服务管理：/etc/init.d/服务名 start/restart/enable
   - 防火墙：/etc/config/firewall，规则改完执行 /etc/init.d/firewall restart
   - 网络配置：/etc/config/network
   - 保存配置：直接编辑配置文件，不需要单独的save命令
   - 常用命令：uci show network / uci show firewall

3. **NAS设备（极空间/群晖等）**：
   - 大多是定制化Linux，没有完整的systemctl
   - SSH服务、用户管理等在Web管理界面操作，不要用systemctl
   - 不要生成save命令

【重要】
- 不要生成save命令（那是网络设备的命令，Linux没有）
- 不要生成system-view（那是华为VRP的命令）
- 根据设备类型选择正确的服务管理命令（systemctl vs /etc/init.d/）
- 配置修改后需要重启服务才生效，用对应的重启命令
""",
}


@app.route("/api/ai/generate", methods=["POST"])
def ai_generate():
    """AI根据自然语言生成设备配置命令"""
    data = request.json
    device_id = data.get("device_id")
    intent = data.get("intent", "")

    devices = load_json(DEVICES_FILE, [])
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "请先选择目标设备"}), 400

    vendor = dev.get("vendor", "leadsec")
    guide = VENDOR_GUIDE.get(vendor, VENDOR_GUIDE["leadsec"])

    prompt = f"""你是网络安全设备配置专家。请根据用户的需求，生成{dev.get('name','该设备')}上的配置命令。

设备信息：
- 厂商：{vendor}
- IP：{dev['ip']}
- 型号：{dev.get('model', '未知')}

{guide}

用户需求：{intent}

请直接输出要在设备上执行的命令序列，每行一条命令。不要解释，不要加markdown代码块标记，只输出纯命令。
重要规则：
- 如果是网络设备（防火墙/交换机），最后加save保存配置
- 如果是Linux系统（服务器/路由器/NAS），不要加save命令，配置改完重启对应服务即可
- 根据设备类型选择正确的命令语法，不要混用不同厂商的命令
"""

    llm = get_llm_config()
    try:
        resp = http_req.post(
            llm["api"],
            headers={"Authorization": f"Bearer {llm['api_key']}"},
            json={
                "model": llm["model"],
                "messages": [
                    {"role": "system", "content": "你是网络设备配置专家，只输出配置命令，不做解释。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 4096
            },
            timeout=120,
        )
        result = resp.json()
        commands_text = result["choices"][0]["message"]["content"]
        # 清理think标签
        import re
        commands_text = re.sub(r"<think>.*?</think>", "", commands_text, flags=re.DOTALL).strip()
        # 去掉markdown代码块
        commands_text = re.sub(r"```\w*\n?", "", commands_text).replace("```", "")
        commands = [c.strip() for c in commands_text.split("\n") if c.strip()]

        return jsonify({
            "ok": True,
            "commands": commands,
            "raw": commands_text,
            "device_name": dev.get("name"),
            "device_ip": dev["ip"],
        })
    except Exception as e:
        return jsonify({"error": f"AI生成失败: {str(e)}"}), 500


# ---------- SSH命令执行 ----------

@app.route("/api/execute", methods=["POST"])
def execute_commands():
    """通过SSH在设备上执行命令（需前端确认后调用）"""
    data = request.json
    device_id = data.get("device_id")
    commands = data.get("commands", [])

    devices = load_json(DEVICES_FILE, [])
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "设备不存在"}), 404

    if not commands:
        return jsonify({"error": "无命令"}), 400

    results = []
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=dev["ip"], port=int(dev.get("ssh_port", 22)),
            username=dev["username"], password=dev["password"],
            timeout=10,
        )

        for cmd in commands:
            try:
                # 对Linux设备自动加sudo（检测是否是网络设备命令）
                is_network_cmd = any(kw in cmd.lower() for kw in [
                    'system-view', 'interface ', 'rule add', 'address add', 'service add',
                    'route ', 'vlan ', 'save', 'display ', 'quit', 'return'
                ])
                # 只有非网络设备命令才加sudo
                if not is_network_cmd and any(kw in cmd for kw in ['systemctl', 'apt', 'yum', 'mkdir', 'chmod', 'chown', 'reboot', 'shutdown']):
                    # 检查是否已经是root
                    stdin, stdout, stderr = client.exec_command(f"echo {dev['password']} | sudo -S {cmd}", timeout=20)
                else:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                results.append({
                    "command": cmd,
                    "output": out[:1000],
                    "error": err[:500],
                    "success": True,
                })
            except Exception as e:
                results.append({
                    "command": cmd,
                    "output": "",
                    "error": str(e),
                    "success": False,
                })

        client.close()

        # 记录日志
        logs = load_json(LOGS_FILE, [])
        logs.append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "device": dev.get("name"),
            "ip": dev["ip"],
            "commands": commands,
            "results": results,
            "user": "admin",
        })
        save_json(LOGS_FILE, logs[-200:])  # 只保留最近200条

        return jsonify({"ok": True, "results": results})

    except Exception as e:
        return jsonify({"error": f"SSH连接失败: {str(e)}"}), 500


# ============================================================
# 配置采集 + 跨厂商翻译
# ============================================================

CONFIG_CMDS = {
    "huawei": "display current-configuration",
    "h3c": "display current-configuration",
    "leadsec": "display current-configuration",
    "cisco": "show running-config",
    "linux": "cat /etc/network/interfaces; cat /etc/config/network; ip route show; iptables -L -n",
}

@app.route("/api/config/collect", methods=["POST"])
def collect_config():
    """采集设备当前配置"""
    data = request.json
    device_id = data.get("device_id")
    devices = load_json(DEVICES_FILE, [])
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "设备不存在"}), 404

    vendor = dev.get("vendor", "leadsec")
    cmd = CONFIG_CMDS.get(vendor, "display current-configuration")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=dev["ip"], port=int(dev.get("ssh_port",22)),
                       username=dev["username"], password=dev["password"], timeout=10)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=20)
        config_text = stdout.read().decode("utf-8", errors="replace")
        client.close()
        return jsonify({"ok": True, "config": config_text, "vendor": vendor, "ip": dev["ip"]})
    except Exception as e:
        return jsonify({"error": f"采集失败: {str(e)}"}), 500


@app.route("/api/llm/config", methods=["GET"])
def get_llm_config_api():
    """获取LLM配置（不返回完整key，只返回前几位和后几位）"""
    config = get_llm_config()
    # 隐藏API Key中间部分，只显示前7位和后4位
    key = config["api_key"]
    if len(key) > 11:
        masked_key = key[:7] + "*" * (len(key) - 11) + key[-4:]
    else:
        masked_key = key
    return jsonify({
        "api": config["api"],
        "model": config["model"],
        "api_key_masked": masked_key,
        "has_key": bool(config["api_key"])
    })


@app.route("/api/llm/config", methods=["POST"])
def save_llm_config_api():
    """保存LLM配置"""
    data = request.json
    config = get_llm_config()
    if data.get("api"):
        config["api"] = data["api"].strip()
    if data.get("model"):
        config["model"] = data["model"].strip()
    # 只有用户填写了新key才更新（不填表示保持不变）
    if data.get("api_key") and data["api_key"] != "********" and "*" not in data["api_key"]:
        config["api_key"] = data["api_key"].strip()
    save_json(LLM_CONFIG_FILE, config)
    return jsonify({"ok": True, "message": "配置已保存"})


@app.route("/api/config/translate", methods=["POST"])
def translate_config():
    """跨厂商配置翻译"""
    data = request.json
    source_config = data.get("config", "")
    source_vendor = data.get("source_vendor", "huawei")
    target_vendor = data.get("target_vendor", "h3c")
    source_model = data.get("source_model", "")
    target_model = data.get("target_model", "")

    if not source_config.strip():
        return jsonify({"error": "配置内容为空"}), 400

    guide = VENDOR_GUIDE.get(target_vendor, VENDOR_GUIDE["leadsec"])

    model_note = ""
    if source_model:
        model_note += f"\n源设备型号/版本: {source_model}"
    if target_model:
        model_note += f"\n目标设备型号/版本: {target_model}（注意不同型号的接口编号、板卡槽位可能不同）"

    prompt = f"""你是网络配置翻译专家。把以下{source_vendor}设备的配置翻译成{target_vendor}设备的等价配置。
{model_note}

翻译规则：
1. 保持配置意图不变（接口、VLAN、ACL、路由、NAT等功能必须完全等价，不能遗漏）
2. 严格使用目标厂商的正确语法，不要混入源厂商的命令
3. 注意跨版本差异：接口编号格式、命令关键字、视图切换方式可能因型号/版本不同而变化
4. 如果源配置中引用了特定板卡/槽位，目标设备接口编号要对应调整
5. 去掉源厂商特有的语法，不要保留原命令
6. 按目标厂商的配置顺序输出
7. 只输出翻译后的配置命令，不要解释、不要加```代码块标记
8. 对于网御星云Power-V，必须严格按照批处理格式输出，所有字段必须完整，不能省略id、active on、comment等参数
9. 地址对象和服务对象要先定义，再在rule中引用
10. 保持原有的规则ID编号逻辑（如果源配置有ID，目标配置也保持对应ID）

目标厂商语法指南：
{guide}

源配置（{source_vendor}）：
{source_config}

请输出{target_vendor}等价配置命令："""

    llm = get_llm_config()
    try:
        resp = http_req.post(
            llm["api"],
            headers={"Authorization": f"Bearer {llm['api_key']}"},
            json={
                "model": llm["model"],
                "messages": [
                    {"role": "system", "content": "你是网络设备配置翻译专家，只输出翻译后的配置命令。"},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 8192
            },
            timeout=90,
        )
        result = resp.json()
        translated = result["choices"][0]["message"]["content"]
        import re as _re
        translated = _re.sub(r"```\w*\n?", "", translated).replace("```", "").strip()
        return jsonify({"ok": True, "translated": translated, "source_vendor": source_vendor, "target_vendor": target_vendor})
    except Exception as e:
        return jsonify({"error": f"翻译失败: {str(e)}"}), 500


@app.route("/api/logs", methods=["GET"])
def get_logs():
    logs = load_json(LOGS_FILE, [])
    return jsonify(list(reversed(logs[-50:])))


# ============================================================
# Web自动化模块（Playwright + AI）
# ============================================================
import base64
import re as _re

WEB_SHOTS_DIR = "/home/lxh/nmap-web/data/screenshots"
os.makedirs(WEB_SHOTS_DIR, exist_ok=True)

@app.route("/data/screenshots/<filename>")
def serve_screenshot(filename):
    return send_from_directory(WEB_SHOTS_DIR, filename)


@app.route("/api/web/execute", methods=["POST"])
def web_execute():
    """通过Playwright在设备Web界面上执行AI生成的操作步骤"""
    data = request.json
    device_id = data.get("device_id")
    intent = data.get("intent", "")

    devices = load_json(DEVICES_FILE, [])
    dev = next((d for d in devices if d.get("id") == device_id), None)
    if not dev:
        return jsonify({"error": "设备不存在"}), 404

    web_url = dev.get("web_url", "")
    if not web_url:
        return jsonify({"error": "该设备未配置Web管理地址，请在设备信息中添加web_url"}), 400

    if not intent:
        return jsonify({"error": "请输入操作需求"}), 400

    steps_log = []
    screenshots = []

    try:
        from playwright.sync_api import sync_playwright
        import glob

        # 自动查找已安装的chromium可执行文件
        chromium_paths = glob.glob("/root/.cache/ms-playwright/chromium-*/chrome-linux*/chrome")
        chromium_exe = chromium_paths[0] if chromium_paths else None

        with sync_playwright() as p:
            launch_kwargs = {"headless": True, "args": ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]}
            if chromium_exe:
                launch_kwargs["executable_path"] = chromium_exe
            browser = p.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800}
            )
            page = context.new_page()

            # Step 1: 打开设备Web页面
            steps_log.append(f"正在访问 {web_url} ...")
            page.goto(web_url, timeout=15000, wait_until="networkidle")
            page.wait_for_timeout(2000)

            shot_path = f"{WEB_SHOTS_DIR}/step_{len(screenshots)}.png"
            page.screenshot(path=shot_path)
            screenshots.append(f"/data/screenshots/step_{len(screenshots)}.png")
            steps_log.append(f"页面已加载: {page.title()}")

            # Step 2: 直接执行登录流程（通用选择器），然后让AI决定后续操作
            # 填用户名
            for sel in ["input[type='text']:first-of-type", "input[name='username']", "input[name='user']", "input#username", "input[type='text']"]:
                try:
                    page.fill(sel, dev["username"], timeout=2000)
                    steps_log.append(f"✓ 已输入用户名")
                    break
                except:
                    continue

            # 填密码
            for sel in ["input[type='password']"]:
                try:
                    page.fill(sel, dev["password"], timeout=2000)
                    steps_log.append(f"✓ 已输入密码")
                    break
                except:
                    continue

            shot_path = f"{WEB_SHOTS_DIR}/step_{len(screenshots)}.png"
            page.screenshot(path=shot_path)
            screenshots.append(f"/data/screenshots/step_{len(screenshots)}.png")

            # 点登录
            for sel in ["button[type='submit']", "input[type='submit']", "text=登录", "text=Login", "text=登陆"]:
                try:
                    page.click(sel, timeout=3000)
                    steps_log.append(f"✓ 已点击登录按钮")
                    break
                except:
                    continue

            page.wait_for_timeout(3000)
            shot_path = f"{WEB_SHOTS_DIR}/step_{len(screenshots)}.png"
            page.screenshot(path=shot_path)
            screenshots.append(f"/data/screenshots/step_{len(screenshots)}.png")
            steps_log.append(f"登录后页面: {page.title()}")

            # Step 3: AI导航 - 提取页面链接，让Qwen3选择要点击的
            try:
                all_links = page.eval_on_selector_all("a, button, .menu-item, .nav-item, li, span", """
                    els => els.map(e => e.textContent.trim()).filter(t => t.length > 0 && t.length < 30)
                """)
                # 去重
                all_links = list(dict.fromkeys(all_links))[:60]
            except:
                all_links = []

            steps_log.append(f"页面发现 {len(all_links)} 个可点击元素")

            ai_prompt = f"""已登录设备Web管理界面。页面标题: {page.title()}
页面菜单: {all_links}
用户需求: {intent}
从菜单列表中选择需要点击的导航项，返回JSON数组，如 ["状态", "网络"]。只输出JSON数组。"""

            try:
                ai_resp = http_req.post(
                    LLM_API,
                    headers={"Authorization": f"Bearer {LLM_API_KEY}"},
                    json={
                        "model": LLM_MODEL,
                        "messages": [
                            {"role": "system", "content": "你是Web导航助手，只输出JSON数组。"},
                            {"role": "user", "content": ai_prompt}
                        ],
                        "temperature": 0.1,
                        "max_tokens": 2000
                    },
                    timeout=60,
                )
                ai_text = ai_resp.json()["choices"][0]["message"]["content"]
            except Exception as ai_err:
                steps_log.append(f"AI导航超时: {str(ai_err)[:50]}")
                ai_text = "[]"

            # 解析AI返回的链接列表
            ai_text = _re.sub(r"<think>.*?</think>", "", ai_text, flags=_re.DOTALL).strip()
            start = ai_text.find("[")
            end = ai_text.rfind("]") + 1
            if start >= 0 and end > start:
                try:
                    click_targets = json.loads(ai_text[start:end])
                except:
                    click_targets = []
            else:
                click_targets = []

            steps_log.append(f"AI建议导航: {click_targets}")

            # 依次点击AI建议的链接
            clicked = 0
            for link_text in click_targets[:5]:
                for link in all_links:
                    if str(link_text).lower() in link.lower() or link.lower() in str(link_text).lower():
                        try:
                            page.click(f"text={link}", timeout=5000)
                            page.wait_for_timeout(2000)
                            shot_path = f"{WEB_SHOTS_DIR}/step_{len(screenshots)}.png"
                            page.screenshot(path=shot_path)
                            screenshots.append(f"/data/screenshots/step_{len(screenshots)}.png")
                            steps_log.append(f"✓ 点击: {link}")
                            clicked += 1
                            break
                        except:
                            continue

            if clicked == 0:
                steps_log.append("未找到匹配菜单，停在首页")

            browser.close()

        # 记录日志
        logs = load_json(LOGS_FILE, [])
        logs.append({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "device": dev.get("name"),
            "ip": dev["ip"],
            "commands": [f"[Web] {intent}"],
            "results": [{"command": "[Web自动化]", "output": "; ".join(steps_log), "success": True}],
            "user": "admin",
        })
        save_json(LOGS_FILE, logs[-200:])

        return jsonify({
            "ok": True,
            "steps": steps_log,
            "screenshots": screenshots,
        })

    except Exception as e:
        return jsonify({"error": f"Web自动化失败: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

