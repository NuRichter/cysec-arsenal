"""
tests/test_recon.py — Unit tests for recon module
NuRichter · CySec Arsenal
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.subdomain_enum import COMMON_SUBDOMAINS
from recon.port_scanner import parse_ports, expand_targets, SERVICE_MAP


class TestSubdomainEnum:
    def test_common_subdomains_not_empty(self):
        assert len(COMMON_SUBDOMAINS) > 10

    def test_common_subdomains_are_strings(self):
        for sub in COMMON_SUBDOMAINS:
            assert isinstance(sub, str)
            assert "." not in sub  # should be bare labels, not FQDNs


class TestPortScanner:
    def test_parse_single_port(self):
        assert parse_ports("80") == [80]

    def test_parse_range(self):
        assert parse_ports("80-83") == [80, 81, 82, 83]

    def test_parse_mixed(self):
        result = parse_ports("22,80,443")
        assert sorted(result) == [22, 80, 443]

    def test_parse_range_and_single(self):
        result = parse_ports("80-82,443")
        assert 80 in result and 81 in result and 443 in result

    def test_expand_single_ip(self):
        targets = expand_targets("192.168.1.1")
        assert targets == ["192.168.1.1"]

    def test_expand_hostname(self):
        targets = expand_targets("example.com")
        assert targets == ["example.com"]

    def test_expand_cidr_small(self):
        targets = expand_targets("192.168.1.0/30")
        # /30 = 4 addresses
        assert len(targets) == 4

    def test_service_map_has_common_ports(self):
        for port in [22, 80, 443, 3306]:
            assert port in SERVICE_MAP


class TestUtils:
    def test_color_ok(self):
        from utils.colors import ok, err, warn, info, found
        assert "[+]" in ok("test")
        assert "[-]" in err("test")
        assert "[!]" in warn("test")
        assert "[*]" in info("test")
        assert "[>]" in found("test")

    def test_logger_returns_logger(self):
        import logging
        from utils.logger import get_logger
        log = get_logger("test_logger")
        assert isinstance(log, logging.Logger)
        # Second call returns same logger (no duplicate handlers)
        log2 = get_logger("test_logger")
        assert log is log2
