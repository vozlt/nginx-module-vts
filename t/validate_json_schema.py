#!/usr/bin/env python3
"""Validate VTS JSON response against the schema expected by the React dashboard.

Reads JSON from stdin. Exits 0 on success, 1 on validation failure.
Error details are printed to stderr.
"""

import json
import sys


def error(msg):
    print(f"SCHEMA ERROR: {msg}", file=sys.stderr)


def check_keys(obj, required_keys, path):
    """Check that all required_keys exist in obj. Returns list of errors."""
    errors = []
    for key in required_keys:
        if key not in obj:
            errors.append(f"Missing key '{key}' in {path}")
    return errors


def validate_responses(obj, path):
    """Validate a Responses object."""
    return check_keys(obj, ["1xx", "2xx", "3xx", "4xx", "5xx"], path)


def validate_cache_responses(obj, path):
    """Validate a CacheZone Responses object."""
    required = [
        "miss", "bypass", "expired", "stale", "updating",
        "revalidated", "hit", "scarce",
    ]
    return check_keys(obj, required, path)


def validate_over_counts(obj, path):
    """Validate an OverCounts object for serverZones/filterZones."""
    required = [
        "maxIntegerSize", "requestCounter", "inBytes", "outBytes",
        "1xx", "2xx", "3xx", "4xx", "5xx",
        "miss", "bypass", "expired", "stale", "updating",
        "revalidated", "hit", "scarce", "requestMsecCounter",
    ]
    return check_keys(obj, required, path)


def validate_upstream_over_counts(obj, path):
    """Validate an OverCounts object for upstreamZones."""
    required = [
        "maxIntegerSize", "requestCounter", "inBytes", "outBytes",
        "1xx", "2xx", "3xx", "4xx", "5xx",
        "requestMsecCounter", "responseMsecCounter",
    ]
    return check_keys(obj, required, path)


def validate_server_zone(obj, path):
    """Validate a ServerZone object."""
    errors = check_keys(
        obj,
        ["requestCounter", "inBytes", "outBytes", "responses", "overCounts"],
        path,
    )
    if "responses" in obj:
        errors.extend(validate_responses(obj["responses"], f"{path}.responses"))
    if "overCounts" in obj:
        errors.extend(validate_over_counts(obj["overCounts"], f"{path}.overCounts"))
    return errors


def validate_upstream_peer(obj, path):
    """Validate an UpstreamPeer object."""
    required = [
        "server", "requestCounter", "inBytes", "outBytes", "responses",
        "weight", "maxFails", "failTimeout", "backup", "down",
    ]
    errors = check_keys(obj, required, path)
    if "responses" in obj:
        errors.extend(validate_responses(obj["responses"], f"{path}.responses"))
    if "overCounts" in obj:
        errors.extend(validate_upstream_over_counts(obj["overCounts"], f"{path}.overCounts"))
    return errors


def validate_cache_over_counts(obj, path):
    """Validate an OverCounts object for cacheZones."""
    required = [
        "maxIntegerSize", "inBytes", "outBytes",
        "miss", "bypass", "expired", "stale", "updating",
        "revalidated", "hit", "scarce",
    ]
    return check_keys(obj, required, path)


def validate_cache_zone(obj, path):
    """Validate a CacheZone object."""
    required = ["maxSize", "usedSize", "inBytes", "outBytes", "responses"]
    errors = check_keys(obj, required, path)
    if "responses" in obj:
        errors.extend(validate_cache_responses(obj["responses"], f"{path}.responses"))
    if "overCounts" in obj:
        errors.extend(validate_cache_over_counts(obj["overCounts"], f"{path}.overCounts"))
    return errors


def validate(data):
    """Validate the top-level VtsResponse object. Returns list of errors."""
    errors = []

    # Top-level required keys
    top_keys = [
        "hostName", "moduleVersion", "nginxVersion",
        "loadMsec", "nowMsec",
        "connections", "sharedZones", "serverZones",
    ]
    errors.extend(check_keys(data, top_keys, "root"))

    # connections
    if "connections" in data:
        conn_keys = ["active", "reading", "writing", "waiting",
                     "accepted", "handled", "requests"]
        errors.extend(check_keys(data["connections"], conn_keys, "connections"))

    # sharedZones
    if "sharedZones" in data:
        sz_keys = ["name", "maxSize", "usedSize", "usedNode"]
        errors.extend(check_keys(data["sharedZones"], sz_keys, "sharedZones"))

    # serverZones
    if "serverZones" in data:
        if not isinstance(data["serverZones"], dict):
            errors.append("serverZones must be an object")
        else:
            for zone_name, zone in data["serverZones"].items():
                errors.extend(validate_server_zone(zone, f"serverZones.{zone_name}"))

    # filterZones (optional)
    if "filterZones" in data:
        if not isinstance(data["filterZones"], dict):
            errors.append("filterZones must be an object")
        else:
            for group_name, group in data["filterZones"].items():
                if not isinstance(group, dict):
                    errors.append(f"filterZones.{group_name} must be an object")
                else:
                    for zone_name, zone in group.items():
                        errors.extend(validate_server_zone(
                            zone, f"filterZones.{group_name}.{zone_name}"))

    # upstreamZones (optional)
    if "upstreamZones" in data:
        if not isinstance(data["upstreamZones"], dict):
            errors.append("upstreamZones must be an object")
        else:
            for group_name, peers in data["upstreamZones"].items():
                if not isinstance(peers, list):
                    errors.append(f"upstreamZones.{group_name} must be an array")
                else:
                    for i, peer in enumerate(peers):
                        errors.extend(validate_upstream_peer(
                            peer, f"upstreamZones.{group_name}[{i}]"))

    # cacheZones (optional)
    if "cacheZones" in data:
        if not isinstance(data["cacheZones"], dict):
            errors.append("cacheZones must be an object")
        else:
            for zone_name, zone in data["cacheZones"].items():
                errors.extend(validate_cache_zone(
                    zone, f"cacheZones.{zone_name}"))

    return errors


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        error(f"Invalid JSON: {e}")
        sys.exit(1)

    errors = validate(data)
    if errors:
        for e in errors:
            error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
