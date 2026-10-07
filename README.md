# Nmap-Web 智能网络安全扫描平台

## 目录

1. [项目介绍](#项目介绍)
2. [功能特性](#功能特性)
3. [部署指南](#部署指南)
4. [使用指南](#使用指南)
5. [AI大模型配置](#ai大模型配置)
6. [Prompt优化流程](#prompt优化流程)
7. [配置说明](#配置说明)
8. [常见问题](#常见问题)

---

## 项目介绍

### 项目简介

Nmap-Web 是一个基于 Flask + Nmap 构建的**智能网络安全扫描与运维自动化平台**。它将传统命令行工具 Nmap 的强大扫描能力，与现代 Web 界面、AI 大模型、跨厂商配置翻译、Web 自动化等技术深度融合，打造出一套"扫描—分析—决策—执行—报表"的闭环工作流。

平台采用深色科技感 UI 设计，无需记忆复杂命令，通过可视化操作即可完成专业级网络安全评估和设备运维工作，同时支持 AI 自然语言交互，让网络运维从"手工敲命令"走向"一句话搞定"。

### 当下面临的需求

随着企业网络规模不断扩大，传统运维方式面临诸多痛点：

1. **工具碎片化**：扫描用 Nmap、登录用 SecureCRT、配置用厂商客户端、报表用 Excel，工具之间数据不互通，效率低下
2. **命令记忆负担重**：不同厂商命令语法差异大（华为 system-view vs H3C system-view vs 网御星云直接命令），运维人员需要同时掌握多套命令体系
3. **跨厂商迁移困难**：设备换代或厂商更换时，配置迁移全靠人工逐条翻译，耗时且易错
4. **AI 能力缺失**：传统工具无法理解自然语言，不能根据业务需求自动生成配置策略
5. **操作不可视化**：SSH 黑盒操作无法直观看到设备 Web 界面的变化，排障困难
6. **报表不规范**：扫描结果散落在终端输出中，难以形成标准化、可归档的安全评估报告
7. **人才门槛高**：专业网络安全运维需要多年经验积累，新人上手慢

### 使用场景

| 场景 | 具体应用 |
|------|----------|
| **等保合规评估** | 定期对内网进行端口和漏洞扫描，生成合规报表，满足等保2.0要求 |
| **设备上线验收** | 新设备入网前进行端口核查、服务识别、漏洞检测，确保安全基线 |
| **日常运维巡检** | 批量检查设备开放端口、运行状态，发现异常服务及时处置 |
| **跨厂商迁移** | 老墙换为新墙、华为换H3C时，一键翻译配置，减少人工工作量 |
| **应急响应** | 安全事件发生后快速扫描受影响网段，定位暴露面和漏洞点 |
| **策略下发** | 用自然语言描述需求（如"禁止某IP访问外网"），AI自动生成命令并执行 |
| **教学实训** | 网络安全专业学生学习端口扫描、漏洞检测、设备配置的实践平台 |
| **中小微企业** | 没有专职安全团队的企业，用低成本工具完成基础安全评估 |

### 核心优势

#### 相比传统 Nmap 命令行

| 对比项 | 传统 Nmap | Nmap-Web |
|--------|-----------|----------|
| 操作方式 | 记忆命令参数，命令行输入 | 可视化界面，点选即可 |
| 结果展示 | 终端文本输出，不易阅读 | 结构化表格 + 统计卡片 + 可视化报表 |
| 报表生成 | 需手动整理或用第三方工具 | 一键导出深色科技感 HTML 报表 |
| 批量管理 | 无设备台账概念 | 内置设备台账，统一管理多设备 |
| AI 能力 | 无 | 自然语言生成命令、配置翻译 |
| 执行闭环 | 只扫描不执行 | 扫描→分析→生成策略→远程执行→报表 |
| 学习成本 | 高（需掌握数十个参数） | 低（图形化操作，开箱即用） |

#### 相比常用运维工具（SecureCRT/Xshell/堡垒机）

| 对比项 | 传统运维工具 | Nmap-Web |
|--------|-------------|----------|
| 核心能力 | 终端登录 + 命令输入 | 扫描 + AI + 执行 + 翻译 + 报表 全链路 |
| 配置翻译 | 人工逐条改写 | AI 自动跨厂商翻译，准确率高 |
| 自然语言 | 不支持 | 支持"一句话下发策略" |
| Web 自动化 | 不支持 | Playwright 驱动浏览器，可视化操作设备 Web 界面 |
| 漏洞扫描 | 不支持 | 内置 NSE 漏洞脚本，CVE/CNVD 识别 |
| 多设备管理 | 会话列表，无结构化台账 | JSON 设备台账，支持厂商/型号/版本标签 |
| 操作审计 | 依赖堡垒机 | 内置操作日志，可追溯 |

#### 技术优势

1. **AI Prompt 工程优化**：针对华为 VRP、H3C Comware、网御星云 Power-V 等主流厂商设备，基于真实生产配置文件打磨专属 Prompt，命令生成准确率大幅提升
2. **多模型兼容**：支持 DeepSeek、通义千问、智谱 AI、本地 Ollama 等多种大模型，可灵活切换
3. **双执行通道**：SSH 命令行 + Web 浏览器自动化，覆盖 CLI 设备和纯 Web 管理设备
4. **零依赖前端**：纯原生 HTML/CSS/JS，无需 Node.js 构建，部署简单
5. **数据本地化**：所有数据存储在本地，不上云，满足内网安全要求
6. **轻量高效**：Python Flask 单文件后端，2GB 内存即可流畅运行

---

## 功能特性

### 1. 端口扫描
- 6种预设扫描模式（快速/标准/深度/操作系统/服务版本/漏洞扫描）
- 自定义端口范围
- 扫描速度调节（T1-T5）
- 实时进度显示
- 扫描结果导出HTML报表

### 2. 漏洞扫描
- 基于Nmap NSE脚本（vuln, vulners）
- CVE/CNVD漏洞编号识别
- 漏洞等级分类（高危/中危/低危）
- 漏洞台账报表生成
- 修复建议参考

### 3. 设备台账管理
- 添加/编辑/删除设备
- 支持多厂商设备（华为/H3C/Cisco/网御星云/Linux）
- 设备IP、端口、账号密码管理
- JSON本地存储

### 4. AI自然语言配置
- 输入自然语言指令，AI自动生成配置命令
- 支持多种设备类型
- 命令预览确认后执行
- 支持SSH命令行和Web自动化两种执行方式

### 5. 跨厂商配置翻译
- 粘贴源设备配置，AI自动翻译成目标厂商命令
- 支持华为VRP ↔ H3C Comware ↔ Cisco IOS ↔ 网御星云
- 支持跨版本转换
- 支持导入配置文件（.txt/.cfg/.conf等）
- 翻译结果导出

### 6. Web自动化操作
- 基于Playwright浏览器自动化
- 可视化操作过程截图
- 支持设备Web管理界面操作

---

## 部署指南

### 环境要求

- **操作系统**：Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- **Python**：3.8+
- **内存**：最低2GB，推荐4GB+
- **磁盘**：最低1GB可用空间
- **网络**：需要访问被扫描设备

### 一键部署（推荐）

```bash
# 1. 下载并解压
unzip nmap-web.zip
cd nmap-web

# 2. 运行部署脚本
sudo bash scripts/install.sh

# 3. 访问平台
# 浏览器打开 http://服务器IP:5000
```

### 手动部署

```bash
# 1. 安装系统依赖
sudo apt-get update
sudo apt-get install -y nmap python3 python3-pip python3-venv

# 2. 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 3. 安装Python依赖
pip install -r requirements.txt

# 4. 安装Playwright浏览器（Web自动化功能需要）
playwright install chromium

# 5. 启动服务
python app.py

# 6. 后台运行（使用systemd）
sudo cp scripts/nmap-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nmap-web
sudo systemctl start nmap-web
```

### Docker部署

```dockerfile
# Dockerfile
FROM python:3.10-slim
RUN apt-get update && apt-get install -y nmap
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN playwright install chromium
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

```bash
docker build -t nmap-web .
docker run -d -p 5000:5000 --name nmap-web nmap-web
```

---

## 使用指南

### 1. 端口扫描

1. 在首页输入扫描目标（IP或网段，如 `192.168.1.0/24`）
2. 选择扫描模式：
   - **快速扫描**：扫前100个常用端口，速度快
   - **标准扫描**：扫前1000个常用端口，推荐
   - **深度扫描**：全端口扫描，较慢但全面
   - **操作系统检测**：识别设备操作系统
   - **服务版本**：识别服务版本号
   - **漏洞扫描**：检测已知漏洞
3. 选择扫描速度（T1慢→T5快）
4. 点击「开始扫描」
5. 等待扫描完成，查看结果
6. 可导出HTML报表

### 2. 设备管理

1. 进入「设备台账」页面
2. 点击「添加设备」
3. 填写设备信息：
   - 设备名称
   - IP地址
   - SSH端口（默认22）
   - 用户名/密码
   - 厂商类型（华为/H3C/Cisco/网御星云/Linux）
   - 型号（选填）
4. 保存后可在AI配置和远程执行中选择该设备

### 3. AI自然语言配置

1. 进入「AI配置」页面
2. 选择目标设备
3. 输入自然语言指令，例如：
   - "允许192.168.1.0/24访问互联网"
   - "禁止192.168.1.100访问外网"
   - "把外网80端口映射到内网192.168.1.100的8080端口"
4. 选择执行方式：
   - **SSH命令行**：通过SSH执行命令
   - **Web自动化**：通过浏览器操作设备Web界面
5. 点击「AI生成命令」
6. 预览生成的命令，确认无误后点击「确认并下发执行」
7. 查看执行结果

### 4. 跨厂商配置翻译

1. 进入「配置翻译」页面
2. 选择源厂商和目标厂商
3. 填写源/目标型号版本（选填，有助于更准确翻译）
4. 粘贴源配置或导入配置文件
5. 点击「AI翻译配置」
6. 查看翻译结果，可复制或导出

### 5. 漏洞扫描

1. 在扫描模式中选择「漏洞扫描」
2. 输入目标IP或网段
3. 开始扫描
4. 扫描完成后查看漏洞列表
5. 点击「生成漏洞报表」导出HTML报表

---

## AI大模型配置

### 配置方式

平台支持在Web界面直接配置AI大模型，无需修改代码：

1. 进入「配置翻译」页面
2. 点击右上角「⚙️ AI模型配置」按钮
3. 填写以下信息：
   - **API地址**：大模型接口地址
   - **模型名称**：模型标识
   - **API Key**：密钥（不修改则保持当前配置）
4. 点击「保存配置」

### 支持的大模型

#### 1. DeepSeek（推荐）
- API地址：`https://api.deepseek.com/v1/chat/completions`
- 模型名称：`deepseek-flash`（快速）或 `deepseek-chat`（高质量）
- 申请地址：https://platform.deepseek.com/

#### 2. 通义千问
- API地址：`https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions`
- 模型名称：`qwen-turbo` 或 `qwen-plus`
- 申请地址：https://dashscope.aliyun.com/

#### 3. 智谱AI
- API地址：`https://open.bigmodel.cn/api/paas/v4/chat/completions`
- 模型名称：`glm-4-flash` 或 `glm-4`
- 申请地址：https://open.bigmodel.cn/

#### 4. 本地部署模型（Ollama）
- API地址：`http://localhost:11434/v1/chat/completions`
- 模型名称：`qwen2:7b` 或 `llama3:8b`
- 需要先安装Ollama并拉取模型

---

## Prompt优化流程

### 核心原理

平台通过精心设计的Prompt（提示词）来引导大模型生成准确的网络设备配置命令。Prompt工程是保证输出准确性的关键。

### Prompt结构

每个厂商的配置生成Prompt包含以下部分：

1. **系统角色定义**：设定AI为网络设备配置专家
2. **设备信息**：厂商、IP、型号
3. **厂商命令指南**：该厂商的完整命令语法参考
4. **用户需求**：自然语言指令
5. **输出规则**：格式要求、注意事项

### 厂商指南优化

厂商指南（VENDOR_GUIDE）是Prompt的核心，位于 `app.py` 中。每个厂商包含：

#### 华为VRP指南
- 视图切换：system-view / quit / return
- 接口配置：interface GigabitEthernet0/0/1
- VLAN配置：vlan batch 10 20
- 路由配置：ip route-static 0.0.0.0 0.0.0.0 192.168.1.1
- ACL配置：acl number 3000
- NAT配置：nat outbound 3000
- 保存：save

#### H3C Comware指南
- 与华为VRP类似，但有关键差异：
- 接口名：GigabitEthernet1/0/1（不是0/0/1）
- VLAN接口：Vlan-interface10
- 包过滤：packet-filter 3000 inbound
- 保存：save force

#### 网御星云Power-V指南
- 直接命令行，不需要system-view
- 接口：interface set phy if eth0 ip ...
- 安全策略：rule add type permit/deny ...
- NAT：rule add type nat/portmap/ipmap ...
- 地址对象：address add name ...
- 服务对象：service add name ...

#### Linux指南
- 区分标准服务器、OpenWrt路由器、NAS设备
- 服务管理：systemctl vs /etc/init.d/
- 防火墙：iptables vs /etc/config/firewall
- 不要生成save命令

### 优化技巧

1. **Few-shot示例**：在指南中加入真实配置示例，AI会模仿示例格式
2. **明确禁止项**：明确告诉AI不要做什么（如"不要用华为的system-view"）
3. **跨版本差异**：标注不同版本的命令差异
4. **参数完整性**：列出所有必要参数，避免AI省略
5. **温度参数**：temperature设为0.1-0.2，降低随机性
6. **max_tokens**：设为4096+，避免长配置被截断

### 自定义厂商指南

如需添加新厂商支持，在 `app.py` 的 `VENDOR_GUIDE` 字典中添加：

```python
VENDOR_GUIDE["new_vendor"] = """新厂商名称
【命令语法】
...
【示例】
...
【注意事项】
...
"""
```

---

## 配置说明

### 数据文件

所有运行时数据存储在 `data/` 目录：

| 文件 | 说明 |
|------|------|
| devices.json | 设备台账（包含账号密码，注意保密） |
| operation_logs.json | 操作日志 |
| llm_config.json | AI模型配置（包含API Key，注意保密） |

### 端口说明

| 端口 | 用途 |
|------|------|
| 5000 | Web管理界面 |

### 服务管理

```bash
# 启动服务
sudo systemctl start nmap-web

# 停止服务
sudo systemctl stop nmap-web

# 重启服务
sudo systemctl restart nmap-web

# 查看状态
sudo systemctl status nmap-web

# 查看日志
journalctl -u nmap-web -f
```

---

## 常见问题

### Q: 扫描不到设备怎么办？
A: 
1. 检查目标IP是否可达（ping测试）
2. 检查防火墙是否拦截扫描
3. 使用深度扫描模式（全端口）
4. 降低扫描速度（T2/T3）避免被IDS拦截

### Q: AI生成的命令不准确怎么办？
A:
1. 在设备台账中正确选择厂商和型号
2. 检查VENDOR_GUIDE是否完善
3. 尝试更换大模型（如deepseek-chat比flash更准确）
4. 在自然语言指令中提供更多细节

### Q: SSH连接失败怎么办？
A:
1. 检查设备IP和端口是否正确
2. 确认SSH服务已开启
3. 检查账号密码
4. 确认网络可达（telnet IP 22测试）

### Q: Web自动化功能无法使用？
A:
1. 确认已安装Playwright：`playwright install chromium`
2. 检查服务器是否有图形环境或安装了依赖库
3. 无头模式可能被部分网站检测，可尝试有头模式

### Q: 如何备份数据？
A: 复制 `data/` 目录即可，包含所有设备配置和日志。

### Q: 支持Windows部署吗？
A: 支持，但推荐Linux。Windows需要手动安装Nmap并配置环境变量，Playwright安装方式相同。

---

## 技术栈

- **后端**：Python Flask
- **扫描引擎**：Nmap + NSE脚本
- **前端**：原生HTML/CSS/JavaScript
- **SSH连接**：Paramiko
- **Web自动化**：Playwright
- **AI接口**：OpenAI兼容API

---

## 许可证

本项目仅供学习和授权测试使用，请勿用于未授权的网络扫描。

## 免责声明

使用本工具进行扫描前，请确保已获得目标网络的书面授权。未经授权的扫描可能违反法律法规。
