# ChainSolver-CTF MCP Server

将 ChainSolver-CTF 重构为 MCP 服务器的 MVP 版本，提供可由 Claude/Cursor 等客户端直接调用的 CTF 工具。

## 已实现（Phase 1 MVP）

- MCP 服务器入口：`src/server.py`
- 区块链基础工具：`decode_transaction`
- CTF 工具箱：`jwt_decode`、`hash_identify`、`decode_string`
- Flag 提取工具：`extract_flags`
- 基础配置：`src/config/settings.py`
- 单元测试：`tests/test_tools.py`

## 项目结构

```text
chainsolver-mcp/
├── src/
│   ├── server.py
│   ├── tools/
│   │   ├── blockchain.py
│   │   ├── ctf_toolbox.py
│   │   └── flag_extraction.py
│   └── config/
│       ├── settings.py
│       └── prompts.yaml
├── tests/
├── requirements.txt
└── setup.py
```

## 安装与运行

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/server.py
```

启动后会打印免责声明：

> This tool is for CTF competitions and authorized security testing only. Do NOT use on systems you don't own or have explicit permission to test.

## Claude Desktop MCP 配置示例

```json
{
  "mcpServers": {
    "chainsolver-ctf": {
      "command": "python",
      "args": ["/absolute/path/to/src/server.py"],
      "env": {
        "ETH_RPC_URL": "https://mainnet.infura.io/v3/YOUR_KEY",
        "MAX_GAS": "1000000"
      }
    }
  }
}
```

## 测试

```bash
pytest -q
```
