"""SF desktop launcher."""
from __future__ import annotations

import sys


def main() -> int:
    try:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            "SF يحتاج إلى واجهة PySide6. ثبّت الاعتمادية داخل بيئة افتراضية "
            'باستخدام: pip install -e ".[desktop]"',
            file=sys.stderr,
        )
        return 2

    from sf_desktop.window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("SF")
    app.setOrganizationName("SF Security Tools")
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
