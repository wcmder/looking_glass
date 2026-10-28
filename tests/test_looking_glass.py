import unittest
import io
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from looking_glass import lookup, LookingGlassError, main, _format_timestamp, _time_zone


class LookupTests(unittest.TestCase):
    def test_short_as_path_per_prefix_ties_and_limit(self):
        import json
        routes = [{"prefix": prefix, "as_path": path}
                  for prefix, path in [("10.22.2.0/24", "1 2 3 3"),
                                       ("10.22.2.0/24", "1 3"),
                                       ("10.22.2.0/24", "2 3"),
                                       ("10.22.0.0/16", "1 2 3"),
                                       ("10.22.0.0/16", "1 2 3 3")]]
        for extra, expected in (([], ["1 3", "2 3", "1 2 3"]),
                                (["--entries-per-prefix", "1"], ["1 3", "1 2 3"])):
            output = io.StringIO()
            with patch("looking_glass.lookup", return_value=routes), redirect_stdout(output):
                self.assertEqual(main(["10.22.2.23", "--short-as-path", "--json", *extra]), 0)
            self.assertEqual([r["as_path"] for r in json.loads(output.getvalue())], expected)
        errors = io.StringIO()
        with patch("looking_glass.lookup", return_value=routes), redirect_stdout(io.StringIO()), redirect_stderr(errors):
            self.assertEqual(main(["10.22.2.23", "--short-as-path"]), 0)
        self.assertIn("Showing 3 of 5 observed routes (2 prefixes)", errors.getvalue())

    def test_entries_per_prefix_limits_each_prefix(self):
        routes = [{"prefix": prefix, "peer": str(index)}
                  for prefix in ("10.22.2.0/24", "10.22.0.0/16")
                  for index in range(3)]
        output, errors = io.StringIO(), io.StringIO()
        with patch("looking_glass.lookup", return_value=routes), redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(main(["10.22.2.23", "--entries-per-prefix", "1"]), 0)
        self.assertEqual(output.getvalue().count("10.22.2.0/24"), 1)
        self.assertEqual(output.getvalue().count("10.22.0.0/16"), 1)
        self.assertIn("Showing 2 of 6 observed routes (2 prefixes)", errors.getvalue())
        output = io.StringIO()
        with patch("looking_glass.lookup", return_value=routes), redirect_stdout(output):
            self.assertEqual(main(["10.22.2.23", "--entries-per-prefix", "2", "--json"]), 0)
        import json
        self.assertEqual(len(json.loads(output.getvalue())), 4)

    def test_invalid_entries_limit(self):
        for limit in ("0", "-1"):
            with patch("looking_glass.lookup") as query, redirect_stderr(io.StringIO()):
                self.assertEqual(main(["8.8.8.8", "--entries-per-prefix", limit]), 1)
            query.assert_not_called()

    def test_timestamp_zones_and_dst(self):
        self.assertEqual(_format_timestamp("2026-07-01T02:00:00Z", _time_zone("EST")),
                         "2026-06-30 21:00:00-05:00")
        self.assertEqual(_format_timestamp("2026-07-01T02:00:00", _time_zone("America/New_York")),
                         "2026-06-30 22:00:00-04:00")
        self.assertEqual(_format_timestamp("2026-01-01T02:00:00+00:00", _time_zone("America/New_York")),
                         "2025-12-31 21:00:00-05:00")
        self.assertEqual(_format_timestamp("2026-01-01T02:00:00", _time_zone("UTC")),
                         "2026-01-01 02:00:00+00:00")

    def test_cli_timestamp_display_and_raw_json(self):
        for provider, field in (("ripe", "latest_time"), ("routeviews", "timestamp")):
            routes = [{"prefix": "8.8.8.0/24", field: "2026-10-28T04:19:57.220000Z"}]
            output = io.StringIO()
            with patch("looking_glass.lookup", return_value=routes), redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["8.8.8.8", "--provider", provider]), 0)
            self.assertIn("(EST)", output.getvalue())
            self.assertIn("2026-10-27 23:19:57.220000-05:00", output.getvalue())
            output = io.StringIO()
            with patch("looking_glass.lookup", return_value=routes), redirect_stdout(output):
                self.assertEqual(main(["8.8.8.8", "--provider", provider, "--json"]), 0)
            self.assertIn(routes[0][field], output.getvalue())

    def test_invalid_zone_fails_before_query(self):
        with patch("looking_glass.lookup") as query, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["8.8.8.8", "--time-zone", "Invalid/Zone"]), 1)
        query.assert_not_called()

    def test_all_covering_prefixes_and_peer_paths(self):
        queried = []

        def api(endpoint, params, timeout):
            resource = params["resource"]
            queried.append(resource)
            prefixes = [resource] if resource in ("8.8.8.0/24", "8.0.0.0/8", "0.0.0.0/0") else []
            return {"rrcs": [{"rrc": "RRC01", "peers": [
                {"prefix": prefix, "peer": peer, "as_path": "1 2"}
                for prefix in prefixes for peer in ("1.1.1.1", "2.2.2.2")]}]}

        with patch("looking_glass._get", side_effect=api):
            routes = lookup("8.8.8.8")
        self.assertEqual(len(queried), 32)
        self.assertEqual(len(routes), 4)
        self.assertEqual(routes[0]["prefix"], "8.8.8.0/24")

    def test_ipv6_enumerates_all_prefix_lengths(self):
        with patch("looking_glass._get", return_value={"rrcs": []}) as api:
            self.assertEqual(lookup("2001:db8::1"), [])
        self.assertEqual(api.call_count, 128)

    def test_default_routes_require_opt_in(self):
        data = {"rrcs": [{"rrc": "RRC01", "peers": [{"prefix": "0.0.0.0/0"}]}]}
        with patch("looking_glass._get", return_value=data):
            self.assertEqual(lookup("10.22.1.0"), [])
            routes = lookup("10.22.1.0", include_default=True)
            self.assertEqual(len(routes), 1)
            self.assertEqual(routes[0]["prefix"], "0.0.0.0/0")
            self.assertEqual(lookup("10.22.1.0", best_match=True), [])

    def test_collector_selection(self):
        data = {"rrcs": [{"rrc": name, "peers": [{"prefix": "8.8.8.0/24"}]}
                         for name in ("RRC00", "RRC01")]}
        with patch("looking_glass.list_servers", return_value=["RRC00", "RRC01"]), \
                patch("looking_glass._get", return_value=data):
            routes = lookup("8.8.8.8", best_match=True, num_servers=1)
        self.assertEqual([r["collector"] for r in routes], ["RRC00"])

    def test_failures_are_not_empty_successes(self):
        with patch("looking_glass._get", side_effect=LookingGlassError("offline")):
            with self.assertRaises(LookingGlassError):
                lookup("8.8.8.8", best_match=True)

    def test_invalid_input(self):
        for address in ("invalid", "8.8.8.8/33"):
            with self.assertRaises(ValueError):
                lookup(address)
        with self.assertRaises(ValueError):
            lookup("8.8.8.8", num_servers=0)

    def test_cidr_discovers_only_contained_prefixes(self):
        def api(endpoint, params, timeout):
            if endpoint == "related-prefixes":
                self.assertEqual(params["resource"], "10.37.0.0/16")
                return {"prefixes": [{"prefix": p} for p in (
                    "10.37.148.0/24", "10.37.148.0/24", "10.36.0.0/16",
                    "10.0.0.0/8", "2001:db8::/32")]}
            return {"rrcs": [{"rrc": "RRC00", "peers": [
                {"prefix": params["resource"], "peer": "1.1.1.1"}]}]}
        with patch("looking_glass._get", side_effect=api) as api_mock:
            routes = lookup("10.37.1.2/16", within=True)
        self.assertEqual({r["prefix"] for r in routes},
                         {"10.37.0.0/16", "10.37.148.0/24"})
        self.assertEqual(api_mock.call_count, 3)

    def test_ipv6_cidr_and_best_match_rejection(self):
        with patch("looking_glass._get", return_value={"prefixes": [], "rrcs": []}):
            self.assertEqual(lookup("2001:db8::/32"), [])
        with self.assertRaises(ValueError):
            lookup("10.37.0.0/16", best_match=True)

    def test_cidr_defaults_to_exact_match(self):
        data = {"rrcs": [{"rrc": "RRC00", "peers": [
            {"prefix": p} for p in ("10.37.0.0/16", "10.37.148.0/24", "10.0.0.0/8")]}]}
        with patch("looking_glass._get", return_value=data) as api:
            routes = lookup("10.37.0.0/16")
        self.assertEqual([r["prefix"] for r in routes], ["10.37.0.0/16"])
        api.assert_called_once_with("looking-glass", {
            "resource": "10.37.0.0/16", "look_back_limit": 86400}, 30)
        with self.assertRaises(ValueError):
            lookup("10.37.0.0", within=True)

    def test_routeviews_matching_and_normalization(self):
        data = [{"prefix": prefix, "origin_asn": 22238, "reporting_peers": [
            {"collector": "route-views3", "peer_addr": "1.2.3.4",
             "as_path": "174 22238", "timestamp": "2026-10-28T00:00:00Z"}]}
            for prefix in ("10.22.4.0/24", "10.22.0.0/16", "0.0.0.0/0")]
        with patch("looking_glass._rv_get", return_value=data) as api:
            routes = lookup("10.22.4.1", provider="routeviews")
            self.assertEqual(len(routes), 2)
            self.assertEqual(routes[0]["peer"], "1.2.3.4")
            self.assertNotIn("latest_time", routes[0])
            api.assert_called_once_with("prefix/10.22.4.1/32", {}, 30)
            exact = lookup("10.22.0.0/16", provider="routeviews")
            self.assertEqual([r["prefix"] for r in exact], ["10.22.0.0/16"])
            best = lookup("10.22.4.1", provider="routeviews", best_match=True)
            self.assertEqual([r["prefix"] for r in best], ["10.22.4.0/24"])

    def test_routeviews_collector_selection(self):
        def api(path, params, timeout):
            if path == "rib/collectors":
                return ["route-views3", "route-views4"]
            return [{"prefix": "8.8.8.0/24", "origin_asn": 15169,
                     "reporting_peers": [{"collector": c, "peer_addr": "1.2.3.4"}
                                         for c in ("route-views3", "route-views4")]}]
        with patch("looking_glass._rv_get", side_effect=api):
            routes = lookup("8.8.8.8", provider="routeviews", num_servers=1)
        self.assertEqual([r["collector"] for r in routes], ["route-views3"])

    def test_unknown_provider_rejected(self):
        with self.assertRaises(ValueError):
            lookup("8.8.8.8", provider="unknown")
