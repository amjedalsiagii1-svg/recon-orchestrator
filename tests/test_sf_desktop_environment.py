"""Unit tests for SF's pure, local scope parser."""
from sf_desktop.environment import parse_scope_lines


def test_parse_scope_lines_accepts_ip_cidr_and_hostname():
    entries, ignored = parse_scope_lines([
        "# comment",
        "",
        "127.0.0.1",
        "192.168.10.0/24",
        "router.home",
    ])
    assert ignored == 2
    assert [entry.valid for entry in entries] == [True, True, True]
    assert [entry.kind for entry in entries] == ["IP", "CIDR", "اسم مضيف"]


def test_parse_scope_lines_rejects_malformed_values():
    entries, _ignored = parse_scope_lines([
        "300.300.300.300/99",
        "300.300.300.300",
        "bad host",
    ])
    assert all(not entry.valid for entry in entries)
