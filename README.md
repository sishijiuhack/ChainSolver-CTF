# ChainSolver-CTF MCP Server

将 ChainSolver-CTF 重构为 MCP 服务器的 MVP 版本，提供可由 Claude Desktop、VS Code（Cline / Continue / 其他支持 MCP 的扩展）、Cursor 等客户端直接调用的 CTF 工具。

## 已实现（Phase 1 MVP）

- MCP 服务器入口：`src/chainsolver_mcp/server.py`
- 区块链基础工具：`decode_transaction`
- CTF 工具箱：`jwt_decode`、`hash_identify`、`decode_string`
- Flag 提取工具：`extract_flags`
- 基础配置：`src/chainsolver_mcp/config/settings.py`
- 单元测试：`tests/test_tools.py`

## 项目结构

```text
chainsolver-ctf/
├── src/
│   ├── chainsolver_mcp/
│   │   ├── server.py
│   │   ├── tools/
│   │   │   ├── blockchain.py
│   │   │   ├── ctf_toolbox.py
│   │   │   └── flag_extraction.py
│   │   └── config/
│   │       ├── settings.py
│   │       └── prompts.yaml
│   └── server.py  # 兼容旧路径的启动包装器
├── tests/
├── requirements.txt
└── setup.py
```

## 安装

### Linux / macOS

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Windows (CMD)

```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install -r requirements.txt
```

## 运行（本地自测）

### 方式 1：直接运行（跨平台）

```bash
python src/server.py
```

### 方式 2：安装后使用 CLI（推荐，跨平台）

```bash
pip install -e .
chainsolver-mcp
```

启动后会打印免责声明：

> This tool is for CTF competitions and authorized security testing only. Do NOT use on systems you don't own or have explicit permission to test.

---

## MCP 客户端配置总览

推荐优先使用 `chainsolver-mcp` 命令作为 `command`，避免不同平台 Python 路径差异。

若你不想安装 CLI，也可以用 `python + src/server.py` 方式。

### 通用 JSON 模板（CLI 方式）

```json
{
  "mcpServers": {
    "chainsolver-ctf": {
      "command": "chainsolver-mcp",
      "args": [],
      "env": {
        "ETH_RPC_URL": "https://mainnet.infura.io/v3/YOUR_KEY",
        "MAX_GAS": "1000000",
        "BIND_HOST": "127.0.0.1"
      }
    }
  }
}
```

### 通用 JSON 模板（Python 方式）

```json
{
  "mcpServers": {
    "chainsolver-ctf": {
      "command": "python",
      "args": ["/absolute/path/to/src/server.py"],
      "env": {
        "ETH_RPC_URL": "https://mainnet.infura.io/v3/YOUR_KEY",
        "MAX_GAS": "1000000",
        "BIND_HOST": "127.0.0.1"
      }
    }
  }
}
```

---

## VS Code 兼容配置（重点）

> 下面给出“可直接复制”的配置方式，适用于 VS Code 中支持 MCP 的扩展（如 Cline / Continue 的 MCP 配置能力）。

### 1）先确认可执行命令

在 VS Code 终端中执行：

```bash
chainsolver-mcp
```

如果提示命令不存在，改用：

```bash
python src/server.py
```

### 2）在扩展的 MCP 配置中新增服务

不同扩展 UI 位置不同，但最终都需要填写以下字段：

- `name`: `chainsolver-ctf`
- `command`: 推荐 `chainsolver-mcp`
- `args`: 推荐 `[]`
- `env`:
  - `ETH_RPC_URL`
  - `MAX_GAS`
  - `BIND_HOST`（建议 `127.0.0.1`）

#### VS Code（Windows）建议配置（CLI）

```json
{
  "mcpServers": {
    "chainsolver-ctf": {
      "command": "chainsolver-mcp",
      "args": [],
      "env": {
        "ETH_RPC_URL": "https://mainnet.infura.io/v3/YOUR_KEY",
        "MAX_GAS": "1000000",
        "BIND_HOST": "127.0.0.1"
      }
    }
  }
}
```

#### VS Code（Windows）回退配置（python 直启）

```json
{
  "mcpServers": {
    "chainsolver-ctf": {
      "command": "python",
      "args": ["C:/absolute/path/to/ChainSolver-CTF/src/server.py"],
      "env": {
        "ETH_RPC_URL": "https://mainnet.infura.io/v3/YOUR_KEY",
        "MAX_GAS": "1000000",
        "BIND_HOST": "127.0.0.1"
      }
    }
  }
}
```

### 3）VS Code 常见问题排查

1. **扩展里启动失败但终端能运行**
   - 原因：扩展进程拿不到你终端激活的 venv。
   - 处理：在配置中直接使用 `python` 绝对路径（venv 里的 python），或先 `pip install -e .` 后使用 `chainsolver-mcp`。

2. **Windows 下路径分隔符问题**
   - 在 JSON 里推荐使用 `/`（如 `C:/.../src/server.py`），可减少转义问题。

3. **命令找不到（`chainsolver-mcp` not found）**
   - 确认已执行 `pip install -e .`。
   - 确认当前 VS Code 使用的是安装该包的 Python 解释器。

4. **RPC 或环境变量未生效**
   - 检查 `env` 是否写在对应 server 节点内。
   - 变量名必须与代码一致：`ETH_RPC_URL`、`MAX_GAS`、`BIND_HOST`。

---

## Claude Desktop 配置示例

```json
{
  "mcpServers": {
    "chainsolver-ctf": {
      "command": "chainsolver-mcp",
      "args": [],
      "env": {
        "ETH_RPC_URL": "https://mainnet.infura.io/v3/YOUR_KEY",
        "MAX_GAS": "1000000",
        "BIND_HOST": "127.0.0.1"
      }
    }
  }
}
```

---

## 测试

```bash
pytest -q
```

## 心流平台（iFlow）qwen3-235b 测试

> 你反馈的 `INVALID_JSON_RESPONSE + HTML 页面` 是因为请求命中了站点页，而非模型 API 端点。

仓库脚本已内置端点兜底与 HTML 识别诊断，优先尝试：

- `https://platform.iflow.cn/v1/chat/completions`
- `https://platform.iflow.cn/api/openai/v1/chat/completions`

### Linux / macOS

```bash
IFLOW_API_KEY=你的key python scripts/test_iflow_qwen.py
```

### Windows PowerShell

```powershell
$env:IFLOW_API_KEY="你的key"
python scripts/test_iflow_qwen.py
```

### 显式指定端点（推荐）

```bash
IFLOW_API_KEY=你的key IFLOW_API_URL=https://platform.iflow.cn/v1/chat/completions python scripts/test_iflow_qwen.py
```

可选环境变量：

- `IFLOW_API_URL`：手动指定 API 端点
- `IFLOW_MODEL`（默认：`qwen3-235b`）
- `IFLOW_TIMEOUT_S`（默认：`30`）

如果再次出现 HTML 响应，优先检查：

1. 端点是否是 `platform.iflow.cn` 而不是 `api.iflow.cn`。
2. API Key 是否有效、是否有该模型调用权限。
3. 网络代理是否拦截了 HTTPS 出站请求。
