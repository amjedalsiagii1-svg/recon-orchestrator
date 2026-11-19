"""Offline-only tests for SF scope policy."""
from sf_desktop.scope_guard import ScopePolicy, validate_scope_entry


def test_private_ip_and_small_network_are_accepted():
    assert validate_scope_entry("192.168.8.10").allowed
    assert validate_scope_entry("192.168.8.0/24").allowed


def test_public_network_hostname_and_oversized_network_are_rejected():
    assert not validate_scope_entry("8.8.8.8").allowed
    assert not validate_scope_entry("example.com").allowed
    assert not validate_scope_entry("10.0.0.0/8").allowed


def test_target_must_be_literal_and_inside_scope():
    policy = ScopePolicy.from_values(["192.168.8.0/24"])
    assert policy.authorize_target("192.168.8.12").allowed
    assert not policy.authorize_target("192.168.9.12").allowed
    assert not policy.authorize_target("router.local").allowed
    assert not policy.authorize_target("8.8.8.8").allowed


def test_requested_cidr_must_be_a_bounded_subnet():
    policy = ScopePolicy.from_values(["192.168.8.0/24"])
    assert policy.authorize_network("192.168.8.0/25").allowed
    assert not policy.authorize_network("192.168.0.0/16").allowed
