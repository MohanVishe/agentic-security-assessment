"""nmap: port and service discovery (TCP connect scan, top 100 ports + the target's own port)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .common import Target, finding, run_command

SPEC = {
    "name": "nmap",
    "title": "Nmap port and service discovery",
    "description": "TCP connect scan of the 100 most common ports with service/version detection. "
    "Shows which network services the host exposes.",
    "typical_duration": "about 30 seconds",
}

TIMEOUT = 240


def run(target: Target, workdir: Path) -> dict:
    # -sT needs no raw sockets, so it works in an unprivileged container.
    cmd = ["nmap", "-Pn", "-sT", "-sV", "-T4", "--host-timeout", "180s",
           "-p", _ports(target.port), "-oX", "-", target.host]
    status, stdout, stderr = run_command(cmd, TIMEOUT)
    (workdir / "nmap.xml").write_text(stdout, encoding="utf-8")

    findings = parse(stdout) if stdout.strip() else []
    if status == "ok" and not stdout.strip():
        status = "error"
    return {"status": status, "command": " ".join(cmd), "note": stderr.strip()[:300],
            "raw_file": "nmap.xml", "findings": findings}


def parse(xml_text: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    findings = []
    for host in root.iter("host"):
        address = host.find("address")
        ip = address.get("addr", "") if address is not None else ""
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = service.get("name", "unknown") if service is not None else "unknown"
            product = " ".join(
                filter(None, [service.get("product"), service.get("version")])
            ) if service is not None else ""
            # method="table" means nmap could not fingerprint the service and is only
            # guessing from the port number; nmap itself prints such names with a "?".
            guessed = service is not None and service.get("method") == "table"
            label = f"{name}?" if guessed else name
            portid, proto = port.get("portid"), port.get("protocol")
            findings.append(finding(
                id=f"NMAP-{portid}-{proto}",
                tool="nmap",
                title=f"Open port {portid}/{proto} ({label}{' - ' + product if product else ''})",
                url=f"{ip}:{portid}",
                description=f"Port {portid}/{proto} is open. "
                            + (f"nmap could not fingerprint the service; '{name}' is its default guess "
                               f"for this port number." if guessed else
                               f"Service: {name}{' (' + product + ')' if product else ''}."),
                evidence=f"{portid}/{proto} open {label} {product}".strip(),
            ))
    return findings


# nmap's own top-100 TCP list (nmap-services frequencies), so the target's port can be added to it.
TOP_100 = ("7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,"
           "443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,"
           "1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,"
           "5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,"
           "8080-8081,8443,8888,9100,9999-10000,32768,49152-49157")


def _ports(target_port: int) -> str:
    covered = set()
    for part in TOP_100.split(","):
        low, _, high = part.partition("-")
        covered.update(range(int(low), int(high or low) + 1))
    return TOP_100 if target_port in covered else f"{TOP_100},{target_port}"
