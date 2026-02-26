# ChainSolver-CTF MCP Server

基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 的区块链 CTF 解题服务器。让 AI 助手（Claude、Cursor 等）直接调用区块链分析工具，用自然语言驱动"解码 → 分析漏洞 → 生成 PoC → 发送交易 → 提取 flag"全流程。

> **免责声明**：本工具仅用于 CTF 比赛和授权安全测试。请勿在未经授权的系统上使用。

---

## 快速开始

### 1. 环境要求

- Python 3.11+
- Git

### 2. 克隆并安装

```bash
git clone <repo-url>
cd ChainSolver-CTF

# 创建虚拟环境
python -m venv .venv

# 激活（Windows PowerShell）
.\.venv\Scripts\Activate.ps1
# 激活（Windows CMD）
.\.venv\Scripts\activate.bat
# 激活（Linux / macOS）
source .venv/bin/activate

# 安装依赖并注册命令
pip install -e .
```

安装完成后验证：

```bash
chainsolver-mcp
# 应输出：This tool is for CTF competitions and authorized security testing only...
# 然后等待 MCP 客户端连接（Ctrl+C 退出）
```

### 3. 配置环境变量（可选）

复制示例文件并按需填写：

```bash
cp .env.example .env   # 如无此文件，手动创建 .env
```

`.env` 内容示例：

```env
# 区块链 RPC（不填则工具调用时手动传入 rpc_url）
ETH_RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY

# 其他可选项
MAX_GAS=1000000
BIND_HOST=127.0.0.1
```

---

## 接入 MCP 客户端

### VS Code（推荐）

VS Code 1.99+ 原生支持 MCP，项目已内置 [.vscode/mcp.json](.vscode/mcp.json)，**打开项目文件夹后自动生效**，无需额外配置。

手动确认步骤：

1. 用 VS Code 打开 `ChainSolver-CTF` 文件夹
2. `Ctrl+Shift+P` → 输入 `MCP: List Servers`
3. 看到 `chainsolver-ctf` → 点击 ▶ 启动
4. 状态变为 **Running**，显示 `Discovered 25 tools` 即成功

如果启动失败，检查 [.vscode/mcp.json](.vscode/mcp.json) 中的路径是否指向你的 venv：

```json
{
  "servers": {
    "chainsolver-ctf": {
      "type": "stdio",
      "command": ".../ChainSolver-CTF/.venv/Scripts/chainsolver-mcp.exe",
      "args": [],
      "env": {
        "ETH_RPC_URL": "",
        "MAX_GAS": "1000000",
        "BIND_HOST": "127.0.0.1"
      }
    }
  }
}
```

将 `command` 改为你实际的 venv 路径，例如：

```
C:/Users/你的用户名/projects/ChainSolver-CTF/.venv/Scripts/chainsolver-mcp.exe
```

---

### Claude Desktop

编辑 `%APPDATA%\Claude\claude_desktop_config.json`（Windows）或 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）：

```json
{
  "mcpServers": {
    "chainsolver-ctf": {
      "command": "C:/绝对路径/ChainSolver-CTF/.venv/Scripts/chainsolver-mcp.exe",
      "args": [],
      "env": {
        "ETH_RPC_URL": "https://mainnet.infura.io/v3/YOUR_KEY",
        "MAX_GAS": "1000000"
      }
    }
  }
}
```

保存后重启 Claude Desktop，左下角工具栏出现锤子图标即接入成功。

---

### Cursor / Cline / Continue

在对应扩展的 MCP 设置页面填写：

| 字段 | 值 |
|------|----|
| name | `chainsolver-ctf` |
| type | `stdio` |
| command | `.venv/Scripts/chainsolver-mcp.exe` 的绝对路径 |
| args | （留空） |

---

## 工具一览（25 个）

### 区块链基础工具

| 工具 | 说明 | 关键参数 |
|------|------|---------|
| `decode_transaction_tool` | 解码交易字段（from/to/value/calldata） | `tx_hash` 或 `raw_tx` |
| `decode_event_tool` | 解码交易中的事件日志 | `tx_hash`, `event_signature`, `rpc_url` |
| `call_contract_tool` | 调用只读合约函数（需完整 ABI） | `contract_address`, `abi`, `function_name`, `params`, `rpc_url` |
| `call_contract_raw_tool` | 调用合约函数（只需函数签名，无需 ABI） | `contract_address`, `function_signature`, `rpc_url`, `return_types` |
| `encode_calldata_tool` | 将函数签名 + 参数编码为 hex calldata | `function_signature`, `params` |
| `send_transaction_tool` | 发送交易，支持私钥签名或测试节点解锁账户两种模式 | `to`, `data`, `value`, `rpc_url`, `private_key` 或 `from_address` |
| `get_storage_slots_tool` | 读取合约存储槽，自动解码 Solidity 字符串编码 | `contract_address`, `rpc_url`, `slots` |

**`call_contract_raw_tool` vs `call_contract_tool`**：前者只需传函数签名字符串（如 `"balanceOf(address)"`），更适合 CTF 场景；后者需要完整 ABI JSON。

**`send_transaction_tool` 两种模式**：
- 私钥模式：传 `private_key`，本地签名后广播
- 解锁账户模式：传 `from_address`，依赖 Hardhat/Anvil/Ganache 节点已解锁该账户

---

### 合约漏洞分析工具

| 工具 | 说明 | 关键参数 |
|------|------|---------|
| `analyze_vulnerabilities_tool` | 全量静态分析，检测重入/溢出/权限/delegatecall/时间戳依赖 | `source_code` |
| `detect_reentrancy_tool` | 专项重入检测，附利用思路 | `source_code` |
| `detect_integer_overflow_tool` | 检测整数溢出/下溢（针对 Solidity <0.8） | `source_code` |
| `detect_access_control_tool` | 检测 tx.origin 滥用、selfdestruct、无保护公开函数 | `source_code` |
| `generate_poc_tool` | 生成指定漏洞类型的 Solidity PoC 骨架 | `vulnerability_type`, `contract_address` |

`vulnerability_type` 可选值：`reentrancy` / `integer_overflow` / `access_control` / `delegatecall`

---

### 链上取证工具

| 工具 | 说明 | 关键参数 |
|------|------|---------|
| `trace_funds_tool` | 追踪地址的 ETH 资金流向（多跳） | `address`, `rpc_url`, `depth` |
| `analyze_transaction_flow_tool` | 分析交易的完整调用栈和事件序列 | `tx_hash`, `rpc_url` |
| `decode_storage_tool` | 通过 ABI 读取合约命名状态变量 | `contract_address`, `abi`, `variable_name`, `rpc_url` |

---

### CTF 工具箱

| 工具 | 说明 | 关键参数 |
|------|------|---------|
| `jwt_decode_tool` | 解码 JWT（不验签，用于分析） | `token` |
| `jwt_forge_tool` | 伪造 JWT，支持 HS256/HS512/none 算法 | `payload`, `secret`, `algorithm` |
| `hash_identify_tool` | 根据长度识别哈希算法（MD5/SHA1/SHA256/SHA512） | `hash_string` |
| `hash_crack_tool` | 字典爆破哈希 | `hash_string`, `wordlist`（可选） |
| `decode_string_tool` | 解码 base64 / hex / url 编码 | `encoded_string`, `encoding_type` |
| `xor_bruteforce_tool` | 单/多字节 XOR 爆破，基于英文字频评分 | `ciphertext_hex`, `key_length`（可选） |

---

### Flag 工具

| 工具 | 说明 | 关键参数 |
|------|------|---------|
| `extract_flags_tool` | 从文本中提取 `flag{...}` / `ctf{...}` 格式的 flag | `text`, `pattern`（可选自定义正则） |
| `submit_flag_tool` | 向 CTF 平台提交 flag | `flag`, `challenge_url`, `challenge_id`, `api_key` |

---

### 自动化工作流

| 工具 | 说明 | 关键参数 |
|------|------|---------|
| `auto_solve_challenge_tool` | 自动解题：探测 getFlag/isSolved → 读存储 → 静态分析 | `contract_address`, `rpc_url`, `description`, `setup_contract` |
| `analyze_and_exploit_tool` | 完整流水线：分析漏洞 → 生成 PoC → 尝试利用 → 提取 flag | `contract_address`, `rpc_url`, `source_code`, `private_key` 或 `from_address` |

**`auto_solve_challenge_tool` 工作流程**：
1. 对目标合约和 setup 合约探测 `getFlag()` / `isSolved()` / `flag()` 等常见函数
2. 读取存储槽 0-15，自动解码 Solidity 字符串编码
3. 如提供了源码/描述，执行静态漏洞分析

**`analyze_and_exploit_tool` 工作流程**：
1. 静态分析源码，自动选择最高危漏洞
2. 生成对应 PoC 骨架
3. 如提供了 `setup_contract`，尝试满足条件（如转账）后调用 `getFlag()`
4. 扫描存储槽提取 flag

---

## 使用示例

在支持 MCP 的 AI 对话中，直接用自然语言描述需求：

```
帮我解码这个 base64：aGVsbG8gd29ybGQ=
```

```
分析这段 Solidity 代码有没有重入漏洞：
[粘贴合约代码]
```

```
帮我解这道 CTF 题：
- RPC: http://localhost:8545
- 合约地址: 0x1234...
- Setup 合约: 0x5678...
```

```
生成一个针对 0xABCD... 的重入攻击 PoC
```

---

## 项目结构

```
src/chainsolver_mcp/
├── server.py              # MCP 入口，注册所有工具
└── tools/
    ├── blockchain.py      # 区块链基础工具（7个）
    ├── contract_analysis.py # 合约漏洞分析（5个）
    ├── forensics.py       # 链上取证（3个）
    ├── ctf_toolbox.py     # CTF 工具箱（6个）
    ├── flag_extraction.py # Flag 提取与提交（2个）
    └── workflows.py       # 自动化工作流（2个）
```

---

## 常见问题

**Q: MCP server 启动后立即退出？**
确认用的是 venv 里的 `chainsolver-mcp.exe`，不是系统 Python。

**Q: `chainsolver-mcp` 命令找不到？**
重新执行 `pip install -e .`，确认 venv 已激活。

**Q: 工具调用报 `web3 not installed`？**
在 venv 中执行 `pip install web3`。

**Q: VS Code 看不到 `MCP: List Servers` 命令？**
需要 VS Code 1.99 或更高版本。

**Q: 测试 iFlow API 连接？**

```bash
IFLOW_API_KEY=你的key IFLOW_API_URL=https://apis.iflow.cn/v1/chat/completions \
  python scripts/test_iflow_qwen.py
```

---

## 开发

```bash
# 运行测试
pytest -q

# 验证工具数量
python -c "from src.chainsolver_mcp.server import mcp; print('tools:', len(mcp._tool_manager._tools))"
```
