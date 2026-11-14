"""Playbook + Report Enricher Hook"""
import re
from ._utils import render_arg_to_text


def install_playbook_hook():
    import rich.console as rc
    _orig = rc.Console.print
    state = {"ports": [], "target": None, "shown": False, "report_done": False}

    def _extract_ports(txt):
        ports = set()
        for m in re.finditer(r'[│┃]\s*(\d{2,5})\s*[│┃]\s*(tcp|udp)', txt, re.IGNORECASE):
            try:
                ports.add(int(m.group(1)))
            except (ValueError, IndexError):
                pass
        return sorted(ports)

    def _extract_target(txt):
        m = re.search(r'(?:Target|الهدف)\s*[:/]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', txt)
        return m.group(1) if m else None

    def _patched(self, *args, **kwargs):
        _orig(self, *args, **kwargs)
        try:
            for arg in args:
                txt = render_arg_to_text(_orig, self, arg)
                if not txt:
                    continue
                t = _extract_target(txt)
                if t:
                    state["target"] = t
                found = _extract_ports(txt)
                if found:
                    for p in found:
                        if p not in state["ports"]:
                            state["ports"].append(p)
                    state["shown"] = False
                if "Risk Summary" in txt or "ملخص الخطورة" in txt:
                    if state["ports"] and not state["shown"]:
                        state["shown"] = True
                        try:
                            from kali.playbook import build_playbook, display_playbook
                            target = state["target"] or "<target>"
                            pb = build_playbook(state["ports"], target)
                            if pb:
                                display_playbook(pb, target)
                        except Exception:
                            pass
                if "Report Ready" in txt or "التقرير جاهز" in txt:
                    if not state["report_done"]:
                        pm = re.search(r'(reports/output/[\w\-\.]+\.html)', txt)
                        if pm:
                            state["report_done"] = True
                            try:
                                from kali.report_enricher import enrich_report_file
                                target = state["target"] or "<target>"
                                enrich_report_file(pm.group(1), state["ports"], target)
                            except Exception:
                                pass
        except Exception:
            pass

    rc.Console.print = _patched
    return True
