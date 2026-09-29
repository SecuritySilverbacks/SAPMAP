"""Regression tests for sapmap_scanner.parse_targets.

Covers issue #61: a hostname that contains a hyphen (my-host.example.com,
ec2-10-171-11-12.eu-central-1.compute.amazonaws.com) must not be
mistaken for an IPv4 range.
"""
from unittest import mock

import pytest

from sapmap_scanner import parse_targets


def test_hostname_with_single_hyphen_is_not_treated_as_range():
    """A one-hyphen hostname used to hit the range parser, fail
    ipaddress.ip_address('my'), print 'Invalid range' and return []."""
    with mock.patch("sapmap_scanner.socket.gethostbyname",
                    return_value="10.0.0.5") as gethost:
        result = parse_targets("my-host.example.com")
    gethost.assert_called_once_with("my-host.example.com")
    assert result == ["10.0.0.5"]


def test_ec2_style_hostname_resolves():
    """AWS-style hostname with several hyphens must resolve, not be
    treated as a range."""
    with mock.patch("sapmap_scanner.socket.gethostbyname",
                    return_value="10.171.11.12") as gethost:
        result = parse_targets(
            "ec2-10-171-11-12.eu-central-1.compute.amazonaws.com")
    gethost.assert_called_once()
    assert result == ["10.171.11.12"]


def test_ipv4_range_full_form_still_works():
    result = parse_targets("192.168.1.10-192.168.1.12")
    assert result == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def test_ipv4_range_short_form_still_works():
    result = parse_targets("192.168.1.10-12")
    assert result == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def test_single_ip_still_works():
    assert parse_targets("192.168.1.1") == ["192.168.1.1"]


def test_cidr_still_works():
    result = parse_targets("192.168.1.0/30")
    # /30 => 2 usable hosts
    assert result == ["192.168.1.1", "192.168.1.2"]


def test_comma_separated_mixed_hostname_and_ip():
    with mock.patch("sapmap_scanner.socket.gethostbyname",
                    return_value="10.0.0.5"):
        result = parse_targets("my-host.example.com,192.168.1.1")
    assert result == ["10.0.0.5", "192.168.1.1"]
