from chainsolver_mcp.tools.blockchain import decode_transaction
from chainsolver_mcp.tools.ctf_toolbox import decode_string, hash_identify, jwt_decode
from chainsolver_mcp.tools.flag_extraction import extract_flags


def test_decode_transaction_hex_values():
    result = decode_transaction(raw_tx={"hash": "0xabc", "value": "0x10", "chainId": "0x1"})
    assert result["value"] == 16
    assert result["chain_id"] == 1


def test_jwt_decode_parses_payload():
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJjdGYifQ."
    result = jwt_decode(token)
    assert result["header"]["alg"] == "none"
    assert result["payload"]["sub"] == "ctf"


def test_hash_identify_sha256():
    hash_value = "a" * 64
    result = hash_identify(hash_value)
    assert "sha256" in result["candidates"]


def test_decode_string_base64():
    result = decode_string("SGVsbG8=", "base64")
    assert result["decoded"] == "Hello"


def test_extract_flags_default_patterns():
    result = extract_flags("something flag{demo} and FLAG{X}")
    assert result["matches"] == ["flag{demo}", "FLAG{X}"]
