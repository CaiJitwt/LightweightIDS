from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DemoScenario:
    id: str
    title: str
    description: str
    body: str
    expected_rule_ids: frozenset[str]


SCENARIOS = (
    DemoScenario(
        id="benign",
        title="Benign request",
        description="A normal form submission used as a clean comparison.",
        body="message=demo-health-check&status=ok",
        expected_rule_ids=frozenset(),
    ),
    DemoScenario(
        id="sql-injection",
        title="SQL injection signature",
        description="Inert SQL-like text that is never connected to a database.",
        body="query=1%27+UNION+SELECT+username%2Cpassword+FROM+demo_users--",
        expected_rule_ids=frozenset({"SQL_INJECTION"}),
    ),
    DemoScenario(
        id="xss",
        title="XSS signature",
        description="Encoded markup sent as plain text and never rendered by the receiver.",
        body="comment=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E",
        expected_rule_ids=frozenset({"XSS"}),
    ),
    DemoScenario(
        id="path-traversal",
        title="Path traversal signature",
        description="A file-path indicator that is discarded without filesystem access.",
        body="file=..%2F..%2F..%2Fetc%2Fpasswd",
        expected_rule_ids=frozenset({"HTTP_SUSPICIOUS", "WEB_ATTACK"}),
    ),
    DemoScenario(
        id="command",
        title="Command execution signature",
        description="A high-risk command marker sent as text and never executed.",
        body="command=powershell+-enc+DEMO_ONLY_NOT_EXECUTABLE",
        expected_rule_ids=frozenset({"MALICIOUS_COMMAND", "WEB_ATTACK"}),
    ),
    DemoScenario(
        id="template-injection",
        title="Template injection signature",
        description="A template expression that is not evaluated by the receiver.",
        body="template=%7B%7B7%2A7%7D%7D",
        expected_rule_ids=frozenset({"WEB_ATTACK"}),
    ),
    DemoScenario(
        id="ssrf",
        title="SSRF signature",
        description="A metadata-address marker that is never requested or forwarded.",
        body="url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
        expected_rule_ids=frozenset({"HTTP_SUSPICIOUS", "WEB_ATTACK"}),
    ),
)

SCENARIO_BY_ID = {scenario.id: scenario for scenario in SCENARIOS}

