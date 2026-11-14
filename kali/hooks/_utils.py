"""Utility functions for hooks"""
import io
import rich.console as rc


def render_arg_to_text(orig_print, console_self, arg):
    """Render any rich object to plain text via a captured console"""
    try:
        buf = io.StringIO()
        capture = rc.Console(
            record=True, width=300, file=buf,
            force_terminal=False, no_color=True, legacy_windows=False
        )
        orig_print(capture, arg)
        return capture.export_text()
    except Exception:
        try:
            return str(arg)
        except Exception:
            return ""
