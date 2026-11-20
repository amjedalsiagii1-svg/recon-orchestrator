"""Tests for the one-click local read-only audit collector."""
import json
import subprocess

import pytest

from sf_desktop.local_audit import (
    collect_local_snapshot,
    parse_default_route_json,
    parse_ip_address_json,
    parse_local_listeners,
    run_readonly_command,
)


def test_parser_keeps_only_private_and_link_local_addresses():
    raw = json.dumps([
        {
            "ifname": "wlan0",
            "operstate": "UP",
            "address": "aa:bb:cc:dd:ee:ff",
            "addr_info": [
                {"family": "inet", "local": "192.168.8.20", "prefixlen": 24},
                {"family": "inet", "local": "8.8.8.8", "prefixlen": 24},
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                {"family": "inet6", "local": "fe80::1234", "prefixlen": 64},
            ],
        }
    ])
    interfaces, assets = parse_ip_address_json(raw)
    assert interfaces[0]["name"] == "wlan0"
    assert {item["ip"] for item in assets} == {"192.168.8.20", "fe80::1234"}
    assert assets[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_default_route_parser_extracts_gateway_and_device():
    gateway, device = parse_default_route_json(
        '[{"dst":"default","gateway":"192.168.8.1","dev":"wlan0"}]'
    )
    assert gateway == "192.168.8.1"
    assert device == "wlan0"


def test_listener_parser_keeps_tcp_and_udp_ports_without_process_arguments():
    raw = (
        "tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(\"cupsd\",pid=12)\n"
        "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(\"systemd-resolve\",pid=1)\n"
        "tcp ESTAB 0 0 192.168.8.20:44444 192.168.8.1:443\n"
    )
    rows = parse_local_listeners(raw, "192.168.8.20")
    assert [(row["protocol"], row["port"], row["state"]) for row in rows] == [
        ("tcp", 631, "listening"),
        ("udp", 53, "bound"),
    ]
    assert all("pid=" not in (row["extra_info"] or "") for row in rows)


def test_collector_uses_only_fixed_local_commands_and_reads_dns(tmp_path):
    from pathlib import Path

    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.168.8.1\nnameserver invalid\n", encoding="utf-8")
    called = []

    def fake_runner(program, arguments):
        called.append((program, tuple(arguments)))
        if program == "ip" and tuple(arguments) == ("-j", "address", "show"):
            return '[{"ifname":"eth0","operstate":"UP","addr_info":[{"local":"192.168.8.30"}]}]'
        if program == "ip":
            return '[{"dst":"default","gateway":"192.168.8.1","dev":"eth0"}]'
        if program == "ss":
            return "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*"
        raise AssertionError("unexpected command")

    snapshot = collect_local_snapshot(fake_runner, resolv)
    assert snapshot.assets[0]["ip"] == "192.168.8.30"
    assert snapshot.services[0]["port"] == 8080
    assert snapshot.default_gateway == "192.168.8.1"
    assert snapshot.dns_servers == ("192.168.8.1",)
    assert called == [
        ("ip", ("-j", "address", "show")),
        ("ip", ("-j", "route", "show", "default")),
        ("ss", ("-H", "-lntu")),
    ]


def test_command_runner_rejects_any_unlisted_command():
    with pytest.raises(ValueError):
        run_readonly_command("bash", ("-c", "echo unsafe"))
