import xml.etree.ElementTree as ET

from app.extensions import db
from app.models import ScanResult


# Service-name → severity heuristic. Conservative: only services whose mere
# exposure is widely considered a finding in a pentest report.
NMAP_SERVICE_SEVERITY = {
    # Plaintext / no-auth shells & GUIs — almost never legitimate on a modern host
    "telnet":   "High",
    "rsh":      "High",
    "rlogin":   "High",
    "shell":    "High",   # nmap calls rsh on 514 "shell"
    "login":    "High",   # nmap calls rlogin on 513 "login"
    "vnc":      "High",
    "X11":      "High",
    # Backend services that should rarely be internet-exposed
    "mysql":      "Medium",
    "postgresql": "Medium",
    "redis":      "Medium",
    "mongodb":    "Medium",
    "memcached":  "Medium",
    "ajp13":      "Medium",  # Tomcat AJP (Ghostcat surface)
    # Plaintext / info-leak file & directory protocols
    "ftp":          "Medium",
    "ccproxy-ftp":  "Medium",
    "nfs":          "Medium",
    "rpcbind":      "Medium",
    "microsoft-ds": "Medium",
    "netbios-ssn":  "Medium",
    # Mail/remote-management surfaces worth flagging when exposed
    "smtp":   "Low",
    "snmp":   "Low",
}


def parse_nmap_xml(xml_data: str, scan_id: str, target: str):
    """Extract open ports + service banners and persist them as ScanResult rows."""
    if not xml_data or "error" in xml_data:
        print("[PARSER] Invalid Nmap data received.")
        return

    try:
        root = ET.fromstring(xml_data)

        for port in root.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = port.get("portid")
            protocol = port.get("protocol")

            service = port.find("service")
            if service is not None:
                service_name = service.get("name") or "unknown"
                product   = service.get("product")   or ""
                version   = service.get("version")   or ""
                extrainfo = service.get("extrainfo") or ""
            else:
                service_name, product, version, extrainfo = "unknown", "", "", ""

            banner = " ".join(p for p in (product, version, extrainfo) if p).strip()
            severity = NMAP_SERVICE_SEVERITY.get(service_name, "Info")

            finding = f"Open Port: {portid}/{protocol} ({service_name})"
            if banner:
                finding += f" — Banner: {banner}"

            try:
                port_int = int(portid) if portid is not None else None
            except ValueError:
                port_int = None

            db.session.add(ScanResult(
                scan_id=scan_id,
                tool_name="Nmap",
                host=target,
                port=port_int,
                service=service_name,
                finding=finding,
                severity=severity,
                raw_output=ET.tostring(port, encoding="unicode"),
                # Only record product+version when BOTH are present so the
                # correlator's second pass has a tight search query.
                product=product or None,
                version=version or None,
            ))

        db.session.commit()
        print("[PARSER] Nmap XML parsing and database storage complete.")

    except ET.ParseError as e:
        db.session.rollback()
        print(f"[PARSER ERROR] Failed to parse Nmap XML: {e}")
    except Exception as e:
        db.session.rollback()
        print(f"[PARSER ERROR] Nmap parser crashed: {e}")
