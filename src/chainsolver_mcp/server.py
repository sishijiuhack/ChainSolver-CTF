"""ChainSolver-CTF MCP server entrypoint (MVP)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .tools.blockchain import decode_transaction
from .tools.ctf_toolbox import decode_string, hash_identify, jwt_decode
from .tools.flag_extraction import extract_flags

DISCLAIMER = (
    "This tool is for CTF competitions and authorized security testing only. "
    "Do NOT use on systems you don't own or have explicit permission to test."
)

mcp = FastMCP("chainsolver-ctf")


@mcp.tool()
def decode_transaction_tool(tx_hash: str | None = None, raw_tx: dict | None = None) -> dict:
    """Decode transaction data into normalized fields."""

    return decode_transaction(tx_hash=tx_hash, raw_tx=raw_tx)


@mcp.tool()
def jwt_decode_tool(token: str) -> dict:
    """Decode JWT token for CTF analysis."""

    return jwt_decode(token)


@mcp.tool()
def hash_identify_tool(hash_string: str) -> dict:
    """Identify likely hash algorithm."""

    return hash_identify(hash_string)


@mcp.tool()
def decode_string_tool(encoded_string: str, encoding_type: str = "base64") -> dict:
    """Decode encoded input string."""

    return decode_string(encoded_string, encoding_type)


@mcp.tool()
def extract_flags_tool(text: str, pattern: str | None = None) -> dict:
    """Extract flag-like strings from text."""

    return extract_flags(text, pattern)


def main() -> None:
    print(DISCLAIMER)
    mcp.run()


if __name__ == "__main__":
    main()
