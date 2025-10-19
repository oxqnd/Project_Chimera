from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from ..db.database import get_db_connection
from .orchestrator import ask_llm

# Heuristic mappings for advanced reconnaissance
KEYWORD_HINTS: dict[str, dict[str, list[str] | int]] = {
    "admin": {
        "signals": [
            "Subdomain name suggests an administrator control surface."
        ],
        "actions": [
            "Enumerate login flows and enforce MFA/SSO coverage checks.",
            "Attempt default credential and password reuse audit."
        ],
        "weight": 30,
    },
    "portal": {
        "signals": [
            "Naming implies an externally reachable management interface."
        ],
        "actions": [
            "Review authentication controls and brute force protections.",
            "Check for forgotten password and invite flows that leak tokens."
        ],
        "weight": 18,
    },
    "api": {
        "signals": [
            "Likely REST/gRPC surface that may expose privileged actions."
        ],
        "actions": [
            "Diff documented vs discovered endpoints for shadow APIs.",
            "Inspect OpenAPI/GraphQL schemas for sensitive operations."
        ],
        "weight": 16,
    },
    "dev": {
        "signals": [
            "Environment hint indicates development or testing footprint."
        ],
        "actions": [
            "Verify if the host leaks verbose stack traces or debug toggles.",
            "Fingerprint deployment artifacts for stale secrets."
        ],
        "weight": 22,
    },
    "staging": {
        "signals": [
            "Environment naming points to pre-production infrastructure."
        ],
        "actions": [
            "Confirm if staging shares SSO with production tenants.",
            "Search for exposed build artifacts or internal-only endpoints."
        ],
        "weight": 20,
    },
    "internal": {
        "signals": [
            "Label suggests internal-only system reachable from internet."
        ],
        "actions": [
            "Validate IP whitelisting/network ACL drift.",
            "Inspect for unauthenticated administration functionality."
        ],
        "weight": 28,
    },
    "beta": {
        "signals": [
            "Beta rollouts often ship with relaxed security gates."
        ],
        "actions": [
            "Compare feature toggles between beta and production flows.",
            "Probe for experiment-specific parameters lacking validation."
        ],
        "weight": 12,
    },
}

PORT_INSIGHTS: dict[str, dict[str, list[str] | int]] = {
    "22/tcp": {
        "signals": [
            "SSH exposed to the internet."
        ],
        "actions": [
            "Audit SSH hardening (key-only auth, banners, versions).",
            "Check for weak credential reuse across other portals."
        ],
        "weight": 18,
    },
    "3389/tcp": {
        "signals": [
            "RDP exposed; attractive for brute force or ransomware entry."
        ],
        "actions": [
            "Ensure account lockout, MFA, and network segmentation.",
            "Capture screenshot banners for environment fingerprinting."
        ],
        "weight": 26,
    },
    "5432/tcp": {
        "signals": [
            "PostgreSQL database listener exposed."
        ],
        "actions": [
            "Validate TLS configuration and host-based auth.",
            "Attempt metadata-only queries with weak credentials."
        ],
        "weight": 24,
    },
    "3306/tcp": {
        "signals": [
            "MySQL service reachable externally."
        ],
        "actions": [
            "Check for anonymous or weak database accounts.",
            "Review firewall segmentation against production replicas."
        ],
        "weight": 22,
    },
    "6379/tcp": {
        "signals": [
            "Redis exposed and commonly misconfigured without auth."
        ],
        "actions": [
            "Attempt CONFIG GET to test access level.",
            "Assess risk of RCE primitives via module loading."
        ],
        "weight": 24,
    },
    "80/tcp": {
        "signals": [
            "HTTP service without enforced TLS."
        ],
        "actions": [
            "Confirm HTTPS redirect and strict transport security.",
            "Sniff for sensitive headers or verbose error leaks."
        ],
        "weight": 8,
    },
    "443/tcp": {
        "signals": [
            "HTTPS service available."
        ],
        "actions": [
            "Harvest TLS certificate for SAN enumeration.",
            "Check legacy protocol/version support."
        ],
        "weight": 6,
    },
}

VULNERABILITY_HINTS: dict[str, dict[str, list[str] | int]] = {
    "sql injection": {
        "signals": [
            "Automated scanner flagged potential SQL injection entry point."
        ],
        "actions": [
            "Validate parameterized queries and WAF coverage.",
            "Leverage UNION/time-based payloads to confirm exploitability."
        ],
        "weight": 35,
    },
    "cross site scripting": {
        "signals": [
            "Potential reflected or stored cross-site scripting."
        ],
        "actions": [
            "Probe output encoding paths and CSP enforcement.",
            "Test payload variants for account takeover via session theft."
        ],
        "weight": 28,
    },
    "idor": {
        "signals": [
            "Likely insecure direct object reference."
        ],
        "actions": [
            "Enumerate object identifiers for horizontal privilege escalation.",
            "Inspect authorization checks within API gateway or backend."
        ],
        "weight": 32,
    },
    "open redirect": {
        "signals": [
            "Open redirect finding can aid phishing or auth bypass chains."
        ],
        "actions": [
            "Chain redirect with OAuth/SAML flows for token theft.",
            "Harden allow-lists and enforce parameter validation."
        ],
        "weight": 14,
    },
    "sensitive information disclosure": {
        "signals": [
            "Service leaks verbose data useful for further compromise."
        ],
        "actions": [
            "Scrape responses for tokens, keys, or stack traces.",
            "Cross-reference leaked identifiers with other assets."
        ],
        "weight": 20,
    },
}


@dataclass
class ReconInsight:
    asset: str | None
    score: int
    signals: list[str]
    recommended_actions: list[str]

    @property
    def confidence(self) -> str:
        if self.score >= 60:
            return "high"
        if self.score >= 30:
            return "medium"
        return "low"

    def as_dict(self) -> dict:
        return {
            "asset": self.asset,
            "score": min(self.score, 100),
            "signals": self.signals,
            "recommended_actions": self.recommended_actions,
            "confidence": self.confidence,
        }


def _fetch_domain_context(domain: str) -> tuple[list[dict], dict[int, list[dict]]]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, subdomain FROM assets WHERE domain = ?", (domain,))
    assets = [dict(row) for row in cursor.fetchall()]

    if not assets:
        conn.close()
        return [], {}

    asset_ids = [asset["id"] for asset in assets]
    placeholders = ", ".join("?" for _ in asset_ids)

    cursor.execute(
        f"SELECT asset_id, finding, severity FROM vulnerabilities WHERE asset_id IN ({placeholders})",
        asset_ids,
    )
    findings_by_asset: dict[int, list[dict]] = defaultdict(list)
    for row in cursor.fetchall():
        findings_by_asset[row["asset_id"]].append(dict(row))

    conn.close()
    return assets, findings_by_asset


def _apply_keyword_hints(subdomain: str, insight: ReconInsight) -> None:
    lowered = subdomain.lower()
    for keyword, payload in KEYWORD_HINTS.items():
        if keyword in lowered:
            insight.score += int(payload.get("weight", 10))
            insight.signals.extend(payload.get("signals", []))  # type: ignore[arg-type]
            insight.recommended_actions.extend(payload.get("actions", []))  # type: ignore[arg-type]


def _apply_port_hints(vulnerabilities: Iterable[dict], insight: ReconInsight) -> None:
    for vuln in vulnerabilities:
        finding = vuln.get("finding", "")
        if not finding.startswith("Open Port:"):
            continue
        port_info = finding.split("Open Port:")[-1].strip()
        if port_info in PORT_INSIGHTS:
            payload = PORT_INSIGHTS[port_info]
            insight.score += int(payload.get("weight", 6))
            insight.signals.extend(payload.get("signals", []))  # type: ignore[arg-type]
            insight.recommended_actions.extend(payload.get("actions", []))  # type: ignore[arg-type]


def _apply_vulnerability_hints(vulnerabilities: Iterable[dict], insight: ReconInsight) -> None:
    for vuln in vulnerabilities:
        finding = vuln.get("finding", "")
        lowered = finding.lower()
        for keyword, payload in VULNERABILITY_HINTS.items():
            if keyword in lowered:
                insight.score += int(payload.get("weight", 12))
                insight.signals.extend(payload.get("signals", []))  # type: ignore[arg-type]
                insight.recommended_actions.extend(payload.get("actions", []))  # type: ignore[arg-type]


def generate_advanced_recon(domain: str) -> list[dict]:
    assets, findings_by_asset = _fetch_domain_context(domain)
    if not assets:
        return []

    insights: list[ReconInsight] = []
    for asset in assets:
        subdomain = asset["subdomain"]
        asset_findings = findings_by_asset.get(asset["id"], [])
        insight = ReconInsight(asset=subdomain, score=0, signals=[], recommended_actions=[])

        _apply_keyword_hints(subdomain, insight)
        _apply_port_hints(asset_findings, insight)
        _apply_vulnerability_hints(asset_findings, insight)

        if not insight.signals:
            # Provide a default low-priority insight to surface the asset.
            insight.signals.append("No prominent signals detected; monitor for baseline drift.")
            insight.recommended_actions.append(
                "Schedule periodic content discovery (JS, storage buckets, leaked endpoints)."
            )
            insight.score = max(insight.score, 10)

        # Deduplicate strings while preserving order
        insight.signals = list(dict.fromkeys(insight.signals))
        insight.recommended_actions = list(dict.fromkeys(insight.recommended_actions))
        insights.append(insight)

    # Aggregate global insights such as shared certificates or mirrored findings
    if len(assets) >= 2:
        duplicated_keywords = _find_repeated_keywords([asset["subdomain"] for asset in assets])
        if duplicated_keywords:
            signals = [
                f"Multiple assets share the keyword '{kw}', indicating a shared deployment surface."
                for kw in duplicated_keywords
            ]
            actions = [
                "Perform differential analysis between the mirrored hosts for misconfigurations.",
                "Validate shared credentials/configuration profiles are rotated and segregated.",
            ]
            global_insight = ReconInsight(
                asset=None,
                score=32,
                signals=signals,
                recommended_actions=actions,
            )
            insights.append(global_insight)

    # Sort insights by descending score to prioritize the most actionable entries
    ordered = sorted(insights, key=lambda i: i.score, reverse=True)
    return [insight.as_dict() for insight in ordered]


def _find_repeated_keywords(subdomains: Iterable[str]) -> list[str]:
    keyword_counts: defaultdict[str, int] = defaultdict(int)
    for subdomain in subdomains:
        lowered = subdomain.lower()
        for keyword in KEYWORD_HINTS:
            if keyword in lowered:
                keyword_counts[keyword] += 1
    return [kw for kw, count in keyword_counts.items() if count >= 2]


def generate_attack_paths(domain: str) -> list[dict]:
    assets, findings_by_asset = _fetch_domain_context(domain)
    if not assets:
        return []

    structured_context = {
        "domain": domain,
        "assets": [
            {
                "subdomain": asset["subdomain"],
                "findings": findings_by_asset.get(asset["id"], []),
            }
            for asset in assets
        ],
    }

    llm_plan = _ask_llm_for_attack_paths(structured_context)
    if llm_plan:
        return llm_plan

    # Fallback deterministic modeling
    return _heuristic_attack_paths(structured_context)


def _ask_llm_for_attack_paths(context: dict) -> list[dict] | None:
    prompt = f"""
    You are a red team operator performing attack path modeling.
    Given the following reconnaissance context (assets with findings), derive up to three plausible attack paths.
    Each path should explain how an attacker could progress from initial access to impact.

    Context:
    {json.dumps(context, indent=2)}

    Respond strictly as JSON in the format:
    {{
      "paths": [
        {{
          "name": "<short title>",
          "risk": "<low|medium|high>",
          "narrative": "<concise summary>",
          "steps": [
            {{"step": 1, "description": "<detail>", "asset": "<optional>", "evidence": "<optional>"}}
          ]
        }}
      ]
    }}
    """

    raw = ask_llm(prompt)
    if not raw:
        return None

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None

    paths = parsed.get("paths")
    if not isinstance(paths, list):
        return None

    sanitized = []
    for path in paths[:3]:
        name = path.get("name")
        narrative = path.get("narrative")
        steps = path.get("steps", [])
        risk = path.get("risk", "medium")
        if not name or not narrative or not isinstance(steps, list):
            continue

        sanitized_steps = []
        for idx, step in enumerate(steps, start=1):
            description = step.get("description")
            if not description:
                continue
            sanitized_steps.append(
                {
                    "step": idx,
                    "description": description,
                    "asset": step.get("asset"),
                    "evidence": step.get("evidence"),
                }
            )

        if not sanitized_steps:
            continue

        sanitized.append(
            {
                "name": name,
                "risk": risk if risk in {"low", "medium", "high"} else "medium",
                "narrative": narrative,
                "steps": sanitized_steps,
            }
        )

    return sanitized or None


def _heuristic_attack_paths(context: dict) -> list[dict]:
    heuristic_paths: list[dict] = []
    assets = context.get("assets", [])

    # Identify candidate entry points and privilege escalation vectors
    entry_points: list[tuple[str, str]] = []
    escalation_points: list[tuple[str, str]] = []

    for asset in assets:
        subdomain = asset.get("subdomain")
        findings: list[dict] = asset.get("findings", [])
        for finding in findings:
            name = finding.get("finding", "")
            lowered = name.lower()
            if name.startswith("Open Port:"):
                port_info = name.split("Open Port:")[-1].strip()
                if port_info in {"22/tcp open ssh", "3389/tcp open ms-wbt-server"}:
                    entry_points.append((subdomain, port_info))
                elif port_info in {"80/tcp open http", "443/tcp open https"}:
                    escalation_points.append((subdomain, "Exposed web surface"))
            else:
                if any(keyword in lowered for keyword in ("sql injection", "idor", "cross site scripting")):
                    escalation_points.append((subdomain, name))
                if any(keyword in lowered for keyword in ("sensitive", "credential", "token", "secret")):
                    escalation_points.append((subdomain, name))

    if not entry_points and escalation_points:
        # Treat first escalation finding as entry point if none exist
        ep_asset, evidence = escalation_points[0]
        entry_points.append((ep_asset, evidence))

    for idx, (asset, entry_evidence) in enumerate(entry_points[:2], start=1):
        path_steps = [
            {
                "step": 1,
                "description": f"Use exposure '{entry_evidence}' on {asset} to obtain initial foothold.",
                "asset": asset,
                "evidence": entry_evidence,
            }
        ]

        if escalation_points:
            escalation_asset, escalation_evidence = escalation_points[idx % len(escalation_points)]
            path_steps.append(
                {
                    "step": 2,
                    "description": f"Leverage '{escalation_evidence}' on {escalation_asset} to escalate privileges or move laterally.",
                    "asset": escalation_asset,
                    "evidence": escalation_evidence,
                }
            )
        path_steps.append(
            {
                "step": len(path_steps) + 1,
                "description": "Aggregate access to exfiltrate sensitive data or impact business operations.",
                "asset": asset,
            }
        )

        heuristic_paths.append(
            {
                "name": f"Composite Path via {asset}",
                "risk": "high" if "sql injection" in entry_evidence.lower() else "medium",
                "narrative": f"Chain discovered exposures starting at {asset} to drive deeper compromise.",
                "steps": path_steps,
            }
        )

    if not heuristic_paths and assets:
        asset = assets[0].get("subdomain")
        heuristic_paths.append(
            {
                "name": f"Baseline path against {asset}",
                "risk": "low",
                "narrative": "No significant findings; recommend continued reconnaissance and monitoring.",
                "steps": [
                    {
                        "step": 1,
                        "description": f"Revisit {asset} with broader recon (content discovery, JS analysis, source leak hunting).",
                        "asset": asset,
                    }
                ],
            }
        )

    return heuristic_paths[:3]
