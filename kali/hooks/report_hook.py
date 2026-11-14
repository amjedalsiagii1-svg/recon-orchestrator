"""Report Enricher Hook"""
import re


def enrich_report_file(report_path, ports, target):
    try:
        from kali.report_enricher import enrich_report_file as _enrich
        return _enrich(report_path, ports, target)
    except Exception:
        return False
