"""Public RIPE RIS and RouteViews looking glass client."""

import argparse
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import math
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

BASE_URL = "https://stat.ripe.net/data"
_rv_lock = threading.Lock()
_rv_last_request = 0.0


class LookingGlassError(RuntimeError):
    """The remote API failed or returned unusable data."""


def _time_zone(name):
    if name.upper() == "EST":
        return timezone(timedelta(hours=-5), "EST")
    if name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"Unknown time zone: {name}. Use EST, UTC, or an IANA name such as America/New_York") from exc


def _format_timestamp(value, zone):
    if not value:
        return ""
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    # RIPE uses UTC timestamps without an explicit offset.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(zone).isoformat(sep=" ")


def _get(endpoint, params, timeout):
    url = f"{BASE_URL}/{endpoint}/data.json?{urlencode(params)}"
    try:
        request = Request(url, headers={"User-Agent": "internet-looking-glass/0.1"})
        with urlopen(request, timeout=timeout) as response:
            result = json.load(response)
        if result.get("status") != "ok" or not isinstance(result.get("data"), dict):
            raise LookingGlassError(f"{endpoint}: {result.get('messages', 'invalid response')}")
        return result["data"]
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        raise LookingGlassError(f"{endpoint}: {exc}") from exc


def _rv_get(path, params, timeout):
    global _rv_last_request
    # Guest access permits one request per second, including discovery calls.
    with _rv_lock:
        time.sleep(max(0, 1.1 - (time.monotonic() - _rv_last_request)))
        _rv_last_request = time.monotonic()
        url = f"https://api.routeviews.org/{path}?{urlencode(params)}"
        try:
            with urlopen(Request(url, headers={"User-Agent": "internet-looking-glass/0.1"}), timeout=timeout) as response:
                result = json.load(response)
            if not isinstance(result, list):
                raise LookingGlassError(f"RouteViews {path}: expected a list response")
            return result
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            raise LookingGlassError(f"RouteViews {path}: {exc}") from exc


def list_servers(timeout=30, *, provider="ripe"):
    """Return collector IDs for the selected public provider."""
    if provider == "routeviews":
        return sorted(_rv_get("rib/collectors", {}, timeout))
    if provider != "ripe":
        raise ValueError(f"Unknown provider: {provider}")
    return sorted(key.upper() for key in _get("ris-peers", {}, timeout)["peers"])


def lookup(address, *, servers=None, num_servers=None, best_match=False,
           timeout=30, look_back_limit=86400, include_default=False, within=False,
           provider="ripe"):
    """Return routes covering an IP, matching a CIDR exactly, or within a CIDR.

    By default queries every covering prefix except /0. include_default=True
    includes default routes, which do not establish an announcement for the IP.
    best_match=True
    uses the API's single encompassing-prefix lookup. Collector filters apply
    locally; they do not reduce the API response size. Failed queries raise,
    so partial results are never silently represented as complete.
    """
    network = ipaddress.ip_network(address, strict=False) if "/" in address else None
    ip = network.network_address if network else ipaddress.ip_address(address)
    if network is not None and best_match:
        raise ValueError("--best-match applies to IP addresses, not CIDR searches")
    if within and network is None:
        raise ValueError("--within requires a CIDR, e.g. 156.63.0.0/16")
    if not math.isfinite(timeout) or timeout <= 0 or look_back_limit <= 0:
        raise ValueError("timeout and look_back_limit must be positive")
    if num_servers is not None and num_servers <= 0:
        raise ValueError("num_servers must be positive")
    if provider not in ("ripe", "routeviews"):
        raise ValueError(f"Unknown provider: {provider}")
    if provider == "routeviews" and look_back_limit != 86400:
        raise ValueError("--look-back-limit is supported only by RIPE")
    selected = None
    if servers or num_servers is not None:
        available = list_servers(timeout) if provider == "ripe" else list_servers(timeout, provider=provider)
        normalize = str.upper if provider == "ripe" else str.lower
        selected = sorted({normalize(s) for s in servers}) if servers else available
        unknown = set(selected) - set(available)
        if unknown:
            raise ValueError(f"Unknown collectors: {', '.join(sorted(unknown))}")
        if num_servers is not None:
            selected = selected[:num_servers]
    if network is not None and within:
        related = _get("related-prefixes", {"resource": str(network)}, timeout)
        prefixes = {network}
        for entry in related["prefixes"]:
            prefix = ipaddress.ip_network(entry["prefix"])
            if prefix.version == network.version and prefix.subnet_of(network):
                prefixes.add(prefix)
        resources = [str(prefix) for prefix in sorted(
            prefixes, key=lambda p: (int(p.network_address), p.prefixlen))
            if include_default or prefix.prefixlen != 0]
    elif network is not None:
        resources = [str(network)]
    else:
        resources = [f"{ip}/{ip.max_prefixlen}"] if provider == "routeviews" else [str(ip)] if best_match else [
            str(ipaddress.ip_network(f"{ip}/{length}", strict=False))
            for length in range(ip.max_prefixlen, -1 if include_default else 0, -1)
        ]

    def fetch(resource):
        if provider == "routeviews":
            groups = _rv_get(f"prefix/{resource}", {"strict-match": "yes"} if network is not None else {}, timeout)
            routes = []
            for group in groups:
                prefix = ipaddress.ip_network(group["prefix"])
                if prefix.version != ip.version or (prefix.prefixlen == 0 and not include_default):
                    continue
                if network is not None and str(prefix) != resource:
                    continue
                if network is None and ip not in prefix:
                    continue
                for peer in group["reporting_peers"]:
                    if selected is not None and peer["collector"] not in selected:
                        continue
                    routes.append({**peer, "prefix": str(prefix),
                                   "asn_origin": str(group["origin_asn"]),
                                   "peer": peer["peer_addr"],
                                   "community": peer.get("communities", ""),
                                   "rpki_state": group.get("rpki_state"),
                                   "rpki_roas": group.get("rpki_roas"),
                                   "provider": provider})
            return routes
        data = _get("looking-glass", {
            "resource": resource, "look_back_limit": look_back_limit,
        }, timeout)
        routes = []
        for collector in data.get("rrcs", []):
            name = collector["rrc"].upper()
            if selected is not None and name not in selected:
                continue
            for peer in collector.get("peers", []):
                prefix = ipaddress.ip_network(peer["prefix"])
                if prefix.prefixlen == 0 and not include_default:
                    continue
                if prefix.version != ip.version:
                    continue
                if network is not None and not prefix.subnet_of(network):
                    continue
                if network is None and ip not in prefix:
                    continue
                # Exact queries must not accidentally include a fallback prefix.
                if not best_match and str(prefix) != resource:
                    continue
                routes.append({**peer, "collector": name,
                               "location": collector.get("location", "")})
        return routes

    # Keep public API load bounded; at most three simultaneous requests.
    with ThreadPoolExecutor(max_workers=1 if provider == "routeviews" else 3) as pool:
        routes = [route for batch in pool.map(fetch, resources) for route in batch]
    if provider == "routeviews" and best_match and routes:
        longest = max(ipaddress.ip_network(route["prefix"]).prefixlen for route in routes)
        routes = [route for route in routes if ipaddress.ip_network(route["prefix"]).prefixlen == longest]
    return sorted(routes, key=lambda r: (
        int(ipaddress.ip_network(r["prefix"]).network_address) if network is not None else 0,
        -ipaddress.ip_network(r["prefix"]).prefixlen,
        r["collector"], r.get("peer", ""), r.get("as_path", "")))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("ripe", "routeviews"), default="ripe", help="public API provider (default: ripe)")
    parser.add_argument("address", nargs="?", help="IPv4/IPv6 address (containing routes) or CIDR (exact prefix)")
    parser.add_argument("--within", action="store_true", help="find the exact prefix and all more-specific prefixes within a CIDR")
    parser.add_argument("--list-servers", action="store_true", help="list the provider's collector IDs")
    parser.add_argument("-s", "--server", action="append", dest="servers", help="collector ID, e.g. RRC01 (repeatable)")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("-n", "--num-servers", type=int, help="use first N collectors alphabetically (default: 1 unless --server is given)")
    selection.add_argument("--all-servers", action="store_true", help="use all collectors")
    parser.add_argument("--best-match", action="store_true", help="single encompassing-prefix query")
    parser.add_argument("--include-default", action="store_true", help="include /0 routes (not evidence of an IP announcement)")
    parser.add_argument("--json", action="store_true", help="print all route attributes as JSON")
    parser.add_argument("--entries-per-prefix", type=int, metavar="N", help="show at most N peer paths per prefix (default: all)")
    parser.add_argument("--short-as-path", action="store_true", help="keep only the shortest AS paths per prefix (including ties)")
    parser.add_argument("--time-zone", default="EST", help="text timestamp zone: EST (default, fixed UTC-05:00), UTC, or IANA name")
    parser.add_argument("--timeout", type=float, default=30, help="per-request timeout in seconds")
    parser.add_argument("--look-back-limit", type=int, default=86400, help="maximum route confirmation age in seconds")
    args = parser.parse_args(argv)
    try:
        zone = _time_zone(args.time_zone)
        if args.entries_per_prefix is not None and args.entries_per_prefix <= 0:
            raise ValueError("--entries-per-prefix must be positive")
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        if args.list_servers:
            print("\n".join(list_servers(args.timeout, provider=args.provider)))
            return 0
        if not args.address:
            parser.error("address is required unless --list-servers is used")
        num_servers = args.num_servers
        if num_servers is None and not args.servers and not args.all_servers:
            num_servers = 1
        routes = lookup(args.address, servers=args.servers, num_servers=num_servers,
                        best_match=args.best_match, timeout=args.timeout,
                        look_back_limit=args.look_back_limit,
                        include_default=args.include_default, within=args.within,
                        provider=args.provider)
        total_routes = len(routes)
        if args.short_as_path:
            shortest = {}
            for route in routes:
                prefix = route["prefix"]
                length = len(route.get("as_path", "").split())
                shortest[prefix] = min(shortest.get(prefix, float("inf")), length)
            routes = [route for route in routes
                      if len(route.get("as_path", "").split()) == shortest[route["prefix"]]]
        if args.entries_per_prefix is not None:
            counts = {}
            displayed = []
            for route in routes:
                prefix = route["prefix"]
                counts[prefix] = counts.get(prefix, 0) + 1
                if counts[prefix] <= args.entries_per_prefix:
                    displayed.append(route)
            routes = displayed
        if args.json:
            print(json.dumps(routes, indent=2))
        else:
            if not routes:
                print(f"No matching routes observed in {args.provider} for {args.address} with the selected filters.")
                return 0
            zone_label = args.time_zone.upper() if args.time_zone.upper() in ("EST", "UTC") else args.time_zone
            headers = ("PREFIX", "COLLECTOR", "PEER", "ORIGIN ASN", "NEXT HOP", "AS PATH", f"LAST CONFIRMED ({zone_label})")
            keys = ("prefix", "collector", "peer", "asn_origin", "next_hop", "as_path", "latest_time")
            if args.provider == "routeviews":
                headers = (*headers[:-1], f"ROUTE TIMESTAMP ({zone_label})")
                keys = (*keys[:-1], "timestamp")
            rows = [headers] + [tuple(str(route.get(key, "")) for key in keys[:-1]) +
                                (_format_timestamp(route.get(keys[-1]), zone),) for route in routes]
            widths = [max(len(row[index]) for row in rows) for index in range(len(headers))]
            for row in rows:
                print("  ".join(cell.ljust(width) for cell, width in zip(row[:-1], widths[:-1])) + "  " + row[-1])
            if len(routes) < total_routes:
                print(f"Showing {len(routes)} of {total_routes} observed routes ({len({route['prefix'] for route in routes})} prefixes)", file=sys.stderr)
            else:
                print(f"{total_routes} observed routes", file=sys.stderr)
        return 0
    except (LookingGlassError, ValueError, KeyError, TypeError) as exc:
        print(f"lg: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
