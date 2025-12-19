import ipaddress

def validate_scan_input(scan_type: str, target_value: str) -> tuple[bool, str]:
    scan_type = (scan_type or "").strip().lower()
    target_value = (target_value or "").strip()

    if scan_type not in {"url", "ip"}:
        return False, "scan_type must be url or ip"

    if not target_value:
        return False, "target_value is required"

    if scan_type == "ip":
        try:
            ipaddress.ip_address(target_value)
        except ValueError:
            return False, "target_value must be a valid ip address"

    if scan_type == "url":
        lower = target_value.lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            return False, "url must start with http:// or https://"

    return True, ""

def run_mock_scan(scan_type: str, target_value: str) -> tuple[str, str]:
    scan_type = scan_type.strip().lower()
    t = target_value.strip().lower()

    if scan_type == "url":
        if "login" in t or "verify" in t or "update" in t:
            return "suspicious", "url contains common phishing keywords"
        if "free" in t or "bonus" in t or "gift" in t:
            return "suspicious", "url contains high risk lure keywords"
        if t.startswith("https://"):
            return "safe", "https detected and no obvious red flags found"
        return "suspicious", "http detected prefer https"

    if scan_type == "ip":
        ip_obj = ipaddress.ip_address(t)
        if ip_obj.is_private:
            return "safe", "private ip address detected"
        if ip_obj.is_loopback:
            return "safe", "loopback ip address detected"
        if ip_obj.is_multicast:
            return "suspicious", "multicast ip address detected"
        return "suspicious", "public ip address further intel recommended"

    return "suspicious", "unknown scan type"
