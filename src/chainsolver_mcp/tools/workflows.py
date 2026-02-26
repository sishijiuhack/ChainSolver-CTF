"""Automated CTF workflow tools for ChainSolver MCP server."""

from __future__ import annotations

from typing import Any

# Common CTF "solve" function signatures to probe
_SOLVE_SIGNATURES = [
    ("getFlag()", ["string"]),
    ("flag()", ["string"]),
    ("solve()", []),
    ("isSolved()", ["bool"]),
    ("solved()", ["bool"]),
]


def auto_solve_challenge(
    contract_address: str,
    rpc_url: str,
    description: str = "",
    private_key: str | None = None,
    from_address: str | None = None,
    setup_contract: str | None = None,
) -> dict[str, Any]:
    """Attempt to automatically analyze and solve a blockchain CTF challenge.

    Pipeline:
    1. Probe for getFlag()/isSolved() on the target (and optional setup) contract.
    2. Read storage slots 0-15 and decode dynamic strings.
    3. Static analysis if source/description provided.
    4. If a setup contract is given and has a token-balance condition, attempt
       to satisfy it using an unlocked account (from_address) or private_key.

    Args:
        contract_address: Target / Coin contract address.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
        description: Optional challenge description or Solidity source hint.
        private_key: Optional private key for exploit transactions.
        from_address: Optional unlocked sender address (test node).
        setup_contract: Optional Setup contract address to call getFlag() on.
    """
    from .blockchain import get_storage_slots, call_contract_raw, send_transaction
    from .contract_analysis import analyze_vulnerabilities
    from .flag_extraction import extract_flags

    steps: list[dict[str, Any]] = []
    flags_found: list[str] = []

    probe_targets = [contract_address]
    if setup_contract:
        probe_targets.append(setup_contract)

    # Step 1: Probe for flag/solve functions
    for addr in probe_targets:
        for sig, ret_types in _SOLVE_SIGNATURES:
            probe = call_contract_raw(addr, sig, rpc_url, return_types=ret_types or None)
            if "error" not in probe:
                result_val = probe.get("result")
                steps.append({"step": f"probe_{sig}_on_{addr[:10]}", "result": result_val})
                if isinstance(result_val, str) and result_val:
                    found = extract_flags(result_val)["matches"]
                    if found:
                        flags_found.extend(found)

    # Step 2: Read and decode storage slots
    storage = get_storage_slots(contract_address, rpc_url, slots=list(range(16)))
    steps.append({"step": "read_storage", "result": storage})

    for slot, entry in storage.get("slots", {}).items():
        decoded = entry.get("decoded", "") if isinstance(entry, dict) else ""
        raw_hex = entry.get("hex", entry) if isinstance(entry, dict) else entry
        for text in [decoded, raw_hex]:
            if text:
                found = extract_flags(str(text))["matches"]
                if found:
                    flags_found.extend(found)
                    steps.append({"step": f"flag_in_slot_{slot}", "flags": found})

    # Step 3: Static analysis
    if description and len(description) > 50:
        vuln_report = analyze_vulnerabilities(description)
        steps.append({"step": "static_analysis", "result": vuln_report})
        high = [f for f in vuln_report["findings"] if f["severity"] == "high"]
        if high:
            steps.append({"step": "high_severity_findings", "count": len(high),
                          "types": list({f["type"] for f in high})})

    return {
        "contract": contract_address,
        "rpc_url": rpc_url,
        "flags_found": list(dict.fromkeys(flags_found)),
        "steps": steps,
        "solved": len(flags_found) > 0,
        "note": "For exploit execution, use analyze_and_exploit with private_key or from_address.",
    }



def analyze_and_exploit(
    contract_address: str,
    rpc_url: str,
    source_code: str,
    private_key: str = "",
    vulnerability_type: str | None = None,
    from_address: str | None = None,
    setup_contract: str | None = None,
) -> dict[str, Any]:
    """Full analyze → generate PoC → exploit pipeline.

    Args:
        contract_address: Target contract address.
        rpc_url: Ethereum-compatible JSON-RPC endpoint.
        source_code: Solidity source code of the target contract.
        private_key: Attacker private key (hex). Optional if from_address set.
        vulnerability_type: Force a specific vuln type; auto-detected if None.
        from_address: Unlocked sender address for test nodes (no private key needed).
        setup_contract: Setup contract address to call getFlag() after exploit.
    """
    from .contract_analysis import analyze_vulnerabilities, generate_poc
    from .flag_extraction import extract_flags
    from .blockchain import get_storage_slots, call_contract_raw, send_transaction, encode_calldata

    steps: list[dict[str, Any]] = []
    flags_found: list[str] = []

    # Step 1: Analyze
    report = analyze_vulnerabilities(source_code)
    steps.append({"step": "analyze", "summary": report["summary"], "total": report["total"]})

    # Step 2: Pick vulnerability type
    if vulnerability_type:
        vtype = vulnerability_type
    elif report["findings"]:
        for sev in ("high", "medium", "low"):
            hit = next((f for f in report["findings"] if f["severity"] == sev), None)
            if hit:
                vtype = hit["type"]
                break
        else:
            vtype = report["findings"][0]["type"]
    else:
        vtype = "unknown"

    steps.append({"step": "selected_vulnerability", "type": vtype})

    # Step 3: Generate PoC skeleton
    if vtype != "unknown":
        poc = generate_poc(vtype, contract_address)
        steps.append({"step": "generate_poc", "vulnerability_type": vtype})
    else:
        poc = {}

    # Step 4: Attempt exploit if sender available
    sender = from_address or None
    exploited = False

    if (private_key or sender) and setup_contract:
        # Try to satisfy the Setup contract condition by transferring tokens
        # Probe what the setup contract needs
        balance_check = call_contract_raw(
            setup_contract, "isSolved()", rpc_url, return_types=["bool"]
        )
        already_solved = balance_check.get("result") is True
        steps.append({"step": "check_isSolved", "result": already_solved})

        if not already_solved:
            # Try calling getFlag() directly first (might already be satisfied)
            flag_probe = call_contract_raw(
                setup_contract, "getFlag()", rpc_url, return_types=["string"]
            )
            if "error" not in flag_probe and flag_probe.get("result"):
                flags_found.extend(extract_flags(str(flag_probe["result"]))["matches"])
                exploited = True
                steps.append({"step": "getFlag_direct", "result": flag_probe["result"]})
            else:
                # Need to send a transaction to satisfy the condition first
                # Build transfer(setup_contract, 10000) calldata
                transfer_cd = encode_calldata(
                    "transfer(address,uint256)",
                    [setup_contract, 10000],
                )
                if "error" not in transfer_cd:
                    tx_result = send_transaction(
                        to=contract_address,
                        data=transfer_cd["calldata"],
                        value=0,
                        rpc_url=rpc_url,
                        private_key=private_key or None,
                        from_address=sender,
                    )
                    steps.append({"step": "transfer_to_setup", "result": tx_result})

                    if tx_result.get("status") == "success":
                        # Now call getFlag() via a transaction (state-changing)
                        getflag_cd = encode_calldata("getFlag()")
                        tx2 = send_transaction(
                            to=setup_contract,
                            data=getflag_cd["calldata"],
                            value=0,
                            rpc_url=rpc_url,
                            private_key=private_key or None,
                            from_address=sender,
                        )
                        steps.append({"step": "call_getFlag_tx", "result": tx2})

                        # Read flag via eth_call after state is set
                        flag_result = call_contract_raw(
                            setup_contract, "getFlag()", rpc_url, return_types=["string"]
                        )
                        if "error" not in flag_result and flag_result.get("result"):
                            val = str(flag_result["result"])
                            flags_found.extend(extract_flags(val)["matches"] or [val])
                            exploited = True
                            steps.append({"step": "flag_retrieved", "flag": val})

    # Step 5: Scan storage for flags
    storage = get_storage_slots(contract_address, rpc_url, slots=list(range(8)))
    for slot, entry in storage.get("slots", {}).items():
        decoded = entry.get("decoded", "") if isinstance(entry, dict) else ""
        if decoded:
            flags_found.extend(extract_flags(decoded)["matches"])

    return {
        "contract": contract_address,
        "vulnerability_type": vtype,
        "poc_skeleton": poc.get("poc", ""),
        "flags_found": list(dict.fromkeys(flags_found)),
        "steps": steps,
        "exploited": exploited,
        "note": "PoC skeleton generated. Adapt function names and parameters to the actual target.",
    }
