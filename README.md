# Internet BGP looking glass

Python 3.10+ client and `lg` command, with no runtime dependencies.

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
lg 8.8.8.8
lg 2001:4860:4860::8888
lg --list-servers
lg 8.8.8.8 --server RRC01 --server RRC10
lg 8.8.8.8 --num-servers 3
lg 8.8.8.8 --all-servers
lg 8.8.8.8 --best-match --json
lg 8.8.8.8 --include-default
lg 10.37.0.0/16
lg 10.37.0.0/16 --within --all-servers --json
lg 10.22.4.0/24 --provider routeviews
lg --provider routeviews --list-servers
lg 10.22.4.0/24 --time-zone UTC
lg 10.22.4.0/24 --time-zone America/New_York
lg 10.22.2.23 --entries-per-prefix 1
```

For later sessions, run `source .venv/bin/activate` to make `lg` available.
The editable installation picks up changes to the Python source automatically.

Run installation commands from the project directory containing `pyproject.toml`
and `looking_glass.py`. If editable installation reports that `setup.py` or
`setup.cfg` is missing, upgrade pip inside the activated virtual environment
and retry. This project uses `pyproject.toml`; editable installs require
pip 21.3 or newer. Python 3.10 or newer is also required.

Without installation, use `python3 looking_glass.py 8.8.8.8`.

Use `--entries-per-prefix N` to display at most N peer paths for each distinct
prefix, across the selected collectors. Default output includes all paths.
This limits both text and JSON output, preserving the existing route order;
it does not reduce API requests or choose a best path. Text output reports
the displayed count and total observed count when paths are hidden.
For a quick visibility check, use `lg 10.22.2.23 --best-match --entries-per-prefix 1`.
A result means the selected provider/collector observes a route, not proof
of end-to-end reachability.

Use `--short-as-path` to keep only the shortest AS paths for each prefix
across the selected collectors. Ties are retained. Length is the number
of whitespace-separated AS path entries, including repeated ASNs (prepends).
This is an output filter, not the full BGP best-path selection process.
It works with either provider and JSON, and runs before the per-prefix limit:
`lg 10.22.2.23 --short-as-path --entries-per-prefix 1`.

Text timestamps default to **EST (fixed UTC−05:00, year round)**. Select a
different zone with `--time-zone UTC` or an IANA name such as
`--time-zone America/New_York` (automatically uses EST/EDT by date).
The column header identifies the chosen zone and each timestamp includes
its UTC offset. JSON output and the Python API retain original provider
timestamps; this option only controls text display.

`--provider ripe|routeviews` selects the API; RIPE is the default. Both
providers support exact CIDR matches, containing-IP routes, collector selection,
JSON, and `--best-match`. Python calls accept `provider="routeviews"` too.
Collector IDs are provider-specific; discover them with `--list-servers`.

RouteViews guest calls are paced at least 1.1 seconds apart within this
process. An IP lookup uses one route request, which returns all covering
prefixes; selecting collectors adds a discovery request. RouteViews does
not return next-hop data in this endpoint, so that column is blank. Its
timestamp is displayed as `ROUTE TIMESTAMP (EST)` by default and preserved as `timestamp`
in JSON, rather than being presented as a RIPE confirmation timestamp.
`--look-back-limit` applies only to RIPE (non-default values are rejected
for RouteViews). For `--provider routeviews --within`, prefix discovery
still uses RIPE's `related-prefixes` endpoint; paths come from RouteViews.
This mode can miss prefixes absent from RIPE discovery.

Plain IP input finds routes containing the address. CIDR input defaults to
an **exact prefix** lookup, using one looking-glass request.

Add `--within` to CIDR input to find routes **within** that block: the exact prefix and its
more-specific prefixes, excluding larger covering routes and adjacent blocks.
IPv4 and IPv6 are supported; host bits are normalized to the network address.
Discovery uses RIPEstat `related-prefixes`, followed by one looking-glass
request per unique contained prefix (plus the exact input prefix). It does
not scan individual addresses. Results reflect prefixes visible to RIS
discovery and current paths visible at the selected collectors; discovery
and path data can differ in freshness. `--best-match` is only for IP input.
For example, `lookup("10.37.0.0/16", servers=["RRC00"], within=True)` works in Python.

For IP input, RIPE checks **all non-default covering prefixes**, most specific first.
This makes 32 API requests for IPv4 or 128 for IPv6, with
at most three in flight. Use `--best-match` for a single, faster API query
for an encompassing prefix. Each returned peer path is printed; no output
limit is applied. JSON preserves community attributes and timestamps too.

Default routes (`0.0.0.0/0` and `::/0`) are excluded because they do not
establish an announcement for the target address. Add `--include-default`
to include them (one extra request in the default lookup mode). If no routes
are observed, text output says so and JSON output is `[]`. This reflects
RIS visibility and selected filters, not proof of global unreachability.

The CLI defaults to one collector (the first ID alphabetically, currently
RRC00). Text columns are padded to fit the full values. Use `--all-servers`
for all collectors. Explicit `--server` selections are honored in full.
The Python `lookup()` interface continues to default to all collectors.

`--server` selects a RIPE RIS collector ID; `--num-servers N` selects the
first N IDs alphabetically (within `--server` selections if both are given).
These select collector viewpoints within the chosen API provider.
Filtering happens locally and does not reduce response size.
RIPE collector discovery uses RIPEstat's `ris-peers` endpoint;
RouteViews uses `/rib/collectors`.

```python
from looking_glass import lookup, list_servers

print(list_servers())
routes = lookup("8.8.8.8", servers=["RRC01"], best_match=True)
for route in routes:
    print(route["prefix"], route["as_path"], route["peer"])
```

Routes are observations from public RIS peers, not every route on the
Internet or your router's forwarding decision. Data is near real time;
`latest_time` reports route confirmation and `last_updated` reports route
changes. The default confirmation cutoff is 24 hours; change it with
`--look-back-limit SECONDS`. Multiple prefix queries are not an atomic
snapshot. A failed request exits with status 1 instead of reporting partial
data as complete. Empty results are successful and produce an empty JSON list.

API documentation:
- [RIPEstat Looking Glass](https://stat.ripe.net/docs/data-api/api-endpoints/looking-glass)
- [RIPEstat RIS peers](https://stat.ripe.net/docs/data-api/api-endpoints/ris-peers)
- [RIPEstat Related Prefixes](https://stat.ripe.net/docs/data-api/api-endpoints/related-prefixes)
- [RouteViews API](https://api.routeviews.org/docs/)

Run offline tests with `python3 -m unittest discover -s tests`.
