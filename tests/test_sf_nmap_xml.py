"""Tests for strict offline Nmap XML parsing."""
import pytest

from sf_desktop.nmap_xml import NmapImportError, parse_nmap_xml
from sf_desktop.scope_guard import ScopePolicy


SAMPLE = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up"/>
    <address addr="192.168.8.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Vendor"/>
    <hostnames><hostname name="test-device.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>
"""


def test_importer_extracts_scoped_assets_and_services_only():
    scope = ScopePolicy.from_values(["192.168.8.0/24"])
    result = parse_nmap_xml(SAMPLE, source_name="sample.xml", scope=scope)
    assert len(result.assets) == 1
    assert result.assets[0].ip == "192.168.8.10"
    assert result.assets[0].mac == "aa:bb:cc:dd:ee:ff"
    assert result.assets[0].hostname == "test-device.local"
    assert len(result.services) == 2
    assert result.services[0].name == "ssh"
    assert result.skipped_host_count == 1
    assert len(result.sha256) == 64


def test_importer_rejects_non_nmap_xml_and_dtd():
    scope = ScopePolicy.from_values(["192.168.8.0/24"])
    with pytest.raises(NmapImportError):
        parse_nmap_xml(b"<root/>", source_name="bad.xml", scope=scope)
    with pytest.raises(NmapImportError):
        parse_nmap_xml(
            b'<!DOCTYPE x [<!ENTITY y "z">]><nmaprun/>',
            source_name="dtd.xml",
            scope=scope,
        )


def test_importer_requires_at_least_one_authorized_asset():
    scope = ScopePolicy.from_values(["192.168.8.0/24"])
    with pytest.raises(NmapImportError, match="ضمن النطاق"):
        parse_nmap_xml(
            b'<nmaprun><host><status state="up"/>'
            b'<address addr="8.8.8.8" addrtype="ipv4"/>'
            b'</host></nmaprun>',
            source_name="outside.xml",
            scope=scope,
        )


def test_importer_rejects_oversized_xml():
    from sf_desktop.nmap_xml import MAX_XML_BYTES
    scope = ScopePolicy.from_values(["192.168.8.0/24"])
    with pytest.raises(NmapImportError, match="يتجاوز الحد"):
        parse_nmap_xml(b"x" * (MAX_XML_BYTES + 1), source_name="large.xml", scope=scope)
