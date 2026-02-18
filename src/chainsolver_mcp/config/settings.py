"""Runtime settings for ChainSolver-CTF MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    eth_rpc_url: str = os.getenv("ETH_RPC_URL", "")
    max_gas: int = int(os.getenv("MAX_GAS", "1000000"))
    bind_host: str = os.getenv("BIND_HOST", "127.0.0.1")


settings = Settings()
