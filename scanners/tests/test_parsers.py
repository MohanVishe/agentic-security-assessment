"""Each wrapper's parser, fed a small sample of the scanner's real output format."""
import json

import httpx

from tools import nikto, nmap, nuclei, zap
from tools.common import Target

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="172.18.0.2" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="nginx" version="1.25.3" method="probed"/></port>
<port protocol="tcp" portid="3000"><state state="open"/><service name="ppp" method="table"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh" method="table"/></port>
</ports></host></nmaprun>"""

ZAP_ALERTS = [
    {"alertRef": "10038-1", "pluginId": "10038", "name": "Content Security Policy (CSP) Header Not Set",
     "risk": "Medium", "cweid": "693", "url": "http://t/", "evidence": "", "param": "",
     "description": "CSP is missing.", "solution": "Set the header.", "reference": "https://a\nhttps://b"},
    {"alertRef": "10038-1", "pluginId": "10038", "name": "Content Security Policy (CSP) Header Not Set",
     "risk": "Medium", "cweid": "693", "url": "http://t/login", "description": "CSP is missing.",
     "solution": "Set the header.", "reference": ""},
    {"alertRef": "10109", "pluginId": "10109", "name": "Modern Web Application", "risk": "Informational",
     "cweid": "-1", "url": "http://t/", "description": "", "solution": "", "reference": ""},
]

NUCLEI_JSONL = "\n".join([
    json.dumps({"template-id": "prometheus-metrics", "matched-at": "http://t/metrics", "host": "t",
                "info": {"name": "Prometheus Metrics - Detect", "severity": "medium",
                         "classification": {"cvss-score": 5.3, "cwe-id": ["cwe-200"],
                                            "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}}}),
    json.dumps({"template-id": "http-missing-security-headers", "matcher-name": "referrer-policy",
                "matched-at": "http://t", "info": {"name": "HTTP Missing Security Headers", "severity": "info"}}),
    "not json at all",
])

NIKTO_JSON = json.dumps([{"host": "t", "port": "3000", "vulnerabilities": [
    {"id": "001675", "method": "GET", "url": "/ftp/", "msg": "This might be interesting.", "references": ""},
    {"id": "001675", "method": "GET", "url": "/public/", "msg": "This might be interesting.", "references": ""},
    {"id": "001675", "method": "GET", "url": "/ftp/", "msg": "This might be interesting.", "references": ""},
]}])


def test_nmap_reports_open_ports_only_and_flags_guessed_services():
    findings = nmap.parse(NMAP_XML)
    assert [f["id"] for f in findings] == ["NMAP-80-tcp", "NMAP-3000-tcp"]
    assert "nginx 1.25.3" in findings[0]["title"]
    assert "ppp?" in findings[1]["title"]  # nmap only guessed from the port number
    assert all(f["tool_severity"] is None for f in findings)


def test_nmap_bad_xml_gives_no_findings():
    assert nmap.parse("<nmaprun><host>") == []


def test_nmap_port_list_includes_the_target_port_once():
    assert nmap._ports(3000) == nmap.TOP_100
    assert nmap._ports(8090).endswith(",8090")


def test_zap_groups_alert_instances_by_rule():
    findings = zap.parse(ZAP_ALERTS)
    assert [f["id"] for f in findings] == ["ZAP-10038-1", "ZAP-10109"]
    csp = findings[0]
    assert csp["instances"] == 2 and csp["tool_severity"] == "Medium" and csp["cwe"] == "CWE-693"
    assert csp["remediation"] == "Set the header." and csp["references"] == ["https://a", "https://b"]
    assert findings[1]["cwe"] is None


def test_nuclei_keeps_the_scanner_cvss_score_and_skips_bad_lines():
    findings = nuclei.parse(NUCLEI_JSONL)
    assert [f["id"] for f in findings] == ["NUCLEI-prometheus-metrics",
                                           "NUCLEI-http-missing-security-headers:referrer-policy"]
    assert findings[0]["cvss_score"] == 5.3 and findings[0]["cwe"] == "CWE-200"
    assert findings[1]["cvss_score"] is None and findings[1]["tool_severity"] == "info"


def test_nikto_dedupes_and_puts_the_path_in_the_title():
    findings = nikto.parse(NIKTO_JSON)
    assert [f["id"] for f in findings] == ["NIKTO-001675", "NIKTO-001675-2"]
    assert findings[0]["title"] == "/ftp/: This might be interesting."


def test_nikto_repairs_trailing_comma_from_a_time_boxed_run():
    broken = '[{"host": "t", "port": "80", "vulnerabilities": [{"id": "1", "url": "/", "msg": "x"},]}]'
    assert len(nikto.parse(broken)) == 1


def fake_site(monkeypatch, handler):
    """Make the Nikto wrapper's HTTP checks talk to a pretend website."""
    real_client = httpx.Client
    monkeypatch.setattr(nikto.httpx, "Client", lambda **_: real_client(transport=httpx.MockTransport(handler)))


def test_nikto_marks_files_that_are_only_the_catch_all_page(monkeypatch):
    # A single-page app answers every address with its home page; /ftp/ is the only real one here.
    fake_site(monkeypatch, lambda request: httpx.Response(
        200, text="real listing" if request.url.path == "/ftp/" else "<html>app</html>"))
    findings = nikto.parse(NIKTO_JSON)
    nikto.mark_false_alarms(findings, Target(url="http://t:3000"))
    assert [f["likely_false_alarm"] for f in findings] == [False, True]


def test_nikto_results_stand_when_the_site_returns_proper_404s(monkeypatch):
    fake_site(monkeypatch, lambda request: httpx.Response(
        200 if request.url.path in ("/ftp/", "/public/") else 404, text="page"))
    findings = nikto.parse(NIKTO_JSON)
    nikto.mark_false_alarms(findings, Target(url="http://t:3000"))
    assert not any(f["likely_false_alarm"] for f in findings)
