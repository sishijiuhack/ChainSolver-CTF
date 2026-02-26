"""ChainSolver-CTF MCP server entrypoint."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .tools.blockchain import (
    decode_transaction,
    decode_event,
    call_contract,
    call_contract_raw,
    encode_calldata,
    send_transaction,
    get_storage_slots,
)
from .tools.contract_analysis import (
    analyze_vulnerabilities,
    detect_reentrancy,
    detect_integer_overflow,
    detect_access_control,
    generate_poc,
)
from .tools.forensics import (
    trace_funds,
    analyze_transaction_flow,
    decode_storage,
)
from .tools.ctf_toolbox import (
    decode_string,
    hash_identify,
    jwt_decode,
    jwt_forge,
    hash_crack,
    xor_bruteforce,
)
from .tools.flag_extraction import extract_flags, submit_flag
from .tools.workflows import auto_solve_challenge, analyze_and_exploit

DISCLAIMER = (
    "This tool is for CTF competitions and authorized security testing only. "
    "Do NOT use on systems you don't own or have explicit permission to test."
)

mcp = FastMCP("chainsolver-ctf")

# ---------------------------------------------------------------------------
# Blockchain tools
# ---------------------------------------------------------------------------

@mcp.tool()
def decode_transaction_tool(tx_hash: str | None = None, raw_tx: dict | None = None) -> dict:
    """Decode transaction data into normalized fields."""
    return decode_transaction(tx_hash=tx_hash, raw_tx=raw_tx)


@mcp.tool()
def decode_event_tool(tx_hash: str, event_signature: str, rpc_url: str) -> dict:
    """Decode event logs from a transaction matching the given event signature."""
    return decode_event(tx_hash, event_signature, rpc_url)


@mcp.tool()
def call_contract_tool(contract_address: str, abi: list, function_name: str, params: list, rpc_url: str) -> dict:
    """Call a read-only contract function."""
    return call_contract(contract_address, abi, function_name, params, rpc_url)


@mcp.tool()
def send_transaction_tool(
    to: str,
    data: str,
    value: int,
    rpc_url: str,
    private_key: str | None = None,
    from_address: str | None = None,
    gas: int = 300_000,
) -> dict:
    """Sign and broadcast a transaction. Supports private_key mode or unlocked-account mode (test nodes)."""
    return send_transaction(to, data, value, rpc_url, private_key, from_address, gas)


@mcp.tool()
def encode_calldata_tool(function_signature: str, params: list | None = None) -> dict:
    """ABI-encode a function call into hex calldata from a human-readable signature."""
    return encode_calldata(function_signature, params)


@mcp.tool()
def call_contract_raw_tool(
    contract_address: str,
    function_signature: str,
    rpc_url: str,
    params: list | None = None,
    return_types: list | None = None,
) -> dict:
    """Call a contract function using a human-readable signature (no full ABI needed)."""
    return call_contract_raw(contract_address, function_signature, rpc_url, params, return_types)


@mcp.tool()
def get_storage_slots_tool(contract_address: str, rpc_url: str, slots: list | None = None) -> dict:
    """Read raw storage slots from a contract."""
    return get_storage_slots(contract_address, rpc_url, slots)


# ---------------------------------------------------------------------------
# Contract analysis tools
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_vulnerabilities_tool(source_code: str) -> dict:
    """Static analysis of Solidity source code for common CTF vulnerabilities."""
    return analyze_vulnerabilities(source_code)


@mcp.tool()
def detect_reentrancy_tool(source_code: str) -> dict:
    """Focused reentrancy detection with exploit hints."""
    return detect_reentrancy(source_code)


@mcp.tool()
def detect_integer_overflow_tool(source_code: str) -> dict:
    """Detect integer overflow/underflow risks."""
    return detect_integer_overflow(source_code)


@mcp.tool()
def detect_access_control_tool(source_code: str) -> dict:
    """Detect access control weaknesses."""
    return detect_access_control(source_code)


@mcp.tool()
def generate_poc_tool(vulnerability_type: str, contract_address: str, extra: dict | None = None) -> dict:
    """Generate a PoC script skeleton for a given vulnerability type."""
    return generate_poc(vulnerability_type, contract_address, extra)


# ---------------------------------------------------------------------------
# Forensics tools
# ---------------------------------------------------------------------------

@mcp.tool()
def trace_funds_tool(address: str, rpc_url: str, depth: int = 3) -> dict:
    """Trace ETH fund flows from/to an address."""
    return trace_funds(address, rpc_url, depth)


@mcp.tool()
def analyze_transaction_flow_tool(tx_hash: str, rpc_url: str) -> dict:
    """Analyze the full call stack and event sequence of a transaction."""
    return analyze_transaction_flow(tx_hash, rpc_url)


@mcp.tool()
def decode_storage_tool(contract_address: str, abi: list, variable_name: str, rpc_url: str) -> dict:
    """Decode a named storage variable from a contract using its ABI."""
    return decode_storage(contract_address, abi, variable_name, rpc_url)


# ---------------------------------------------------------------------------
# CTF toolbox
# ---------------------------------------------------------------------------

@mcp.tool()
def jwt_decode_tool(token: str) -> dict:
    """Decode JWT token for CTF analysis."""
    return jwt_decode(token)


@mcp.tool()
def jwt_forge_tool(payload: dict, secret: str, algorithm: str = "HS256") -> dict:
    """Forge a JWT token with a given payload and secret."""
    return jwt_forge(payload, secret, algorithm)


@mcp.tool()
def hash_identify_tool(hash_string: str) -> dict:
    """Identify likely hash algorithm."""
    return hash_identify(hash_string)


@mcp.tool()
def hash_crack_tool(hash_string: str, wordlist: list | None = None) -> dict:
    """Attempt to crack a hash against a wordlist."""
    return hash_crack(hash_string, wordlist)


@mcp.tool()
def decode_string_tool(encoded_string: str, encoding_type: str = "base64") -> dict:
    """Decode encoded input string."""
    return decode_string(encoded_string, encoding_type)


@mcp.tool()
def xor_bruteforce_tool(ciphertext_hex: str, key_length: int | None = None) -> dict:
    """Brute-force single or multi-byte XOR cipher."""
    return xor_bruteforce(ciphertext_hex, key_length)


# ---------------------------------------------------------------------------
# Flag tools
# ---------------------------------------------------------------------------

@mcp.tool()
def extract_flags_tool(text: str, pattern: str | None = None) -> dict:
    """Extract flag-like strings from text."""
    return extract_flags(text, pattern)


@mcp.tool()
def submit_flag_tool(flag: str, challenge_url: str, challenge_id: str | None = None, api_key: str | None = None) -> dict:
    """Submit a flag to a CTF platform."""
    return submit_flag(flag, challenge_url, challenge_id, api_key)


# ---------------------------------------------------------------------------
# Workflow tools
# ---------------------------------------------------------------------------

@mcp.tool()
def auto_solve_challenge_tool(
    contract_address: str,
    rpc_url: str,
    description: str = "",
    private_key: str | None = None,
    from_address: str | None = None,
    setup_contract: str | None = None,
) -> dict:
    """Attempt to automatically analyze and solve a blockchain CTF challenge."""
    return auto_solve_challenge(contract_address, rpc_url, description, private_key, from_address, setup_contract)


@mcp.tool()
def analyze_and_exploit_tool(
    contract_address: str,
    rpc_url: str,
    source_code: str,
    private_key: str = "",
    vulnerability_type: str | None = None,
    from_address: str | None = None,
    setup_contract: str | None = None,
) -> dict:
    """Full analyze → generate PoC → exploit pipeline."""
    return analyze_and_exploit(contract_address, rpc_url, source_code, private_key, vulnerability_type, from_address, setup_contract)


def main() -> None:
    print(DISCLAIMER)
    mcp.run()


if __name__ == "__main__":
    main()
