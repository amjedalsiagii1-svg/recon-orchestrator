"""Arabic right-to-left SF desktop shell.

The initial desktop milestone is intentionally read-only. Scan phases are
presented as planned workflow stages and are not wired to the legacy runners.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QAbstractItemView,
    QInputDialog,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sf_desktop.scope_guard import validate_scope_entry
from sf_desktop.storage import SFStore, StoreError
from sf_desktop.reporting import ReportError, generate_session_report
from sf_desktop.environment import (
    PROJECT_ROOT,
    detect_environment,
    list_html_reports,
    read_scope_file,
)


APP_STYLE = """
QMainWindow, QWidget {
    background: #0b1220;
    color: #e5edf7;
    font-family: "Noto Sans Arabic", "Noto Sans", "DejaVu Sans", sans-serif;
    font-size: 13px;
}
QFrame#Sidebar {
    background: #101a2b;
    border-left: 1px solid #26364d;
}
QLabel#BrandMark {
    color: #65d6c5;
    font-size: 30px;
    font-weight: 900;
    letter-spacing: 2px;
}
QLabel#BrandCaption { color: #91a4bd; font-size: 11px; }
QPushButton#NavButton {
    text-align: right;
    padding: 12px 14px;
    color: #aebdd0;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 9px;
    font-weight: 600;
}
QPushButton#NavButton:hover {
    background: #19283c;
    color: #ffffff;
}
QPushButton#NavButton:checked {
    background: #173b43;
    color: #8ee4d5;
    border: 1px solid #286c70;
}
QFrame#TopBar, QFrame#Card, QFrame#Hero, QFrame#Notice {
    background: #111d2e;
    border: 1px solid #26364d;
    border-radius: 13px;
}
QFrame#Hero { background: #102b35; border: 1px solid #23616a; }
QFrame#Notice { background: #2b2518; border: 1px solid #66502b; }
QLabel#PageTitle { font-size: 23px; font-weight: 800; color: #f4f8fc; }
QLabel#SectionTitle { font-size: 16px; font-weight: 700; color: #edf4fb; }
QLabel#Muted { color: #91a4bd; }
QLabel#Metric { font-size: 24px; font-weight: 800; color: #72ddca; }
QLabel#StatusPill {
    background: #2b2518; color: #f0cf83;
    border: 1px solid #66502b; border-radius: 10px;
    padding: 6px 10px; font-weight: 700;
}
QPushButton#ActionButton {
    background: #176b69; color: #ffffff; border: 0;
    padding: 9px 15px; border-radius: 8px; font-weight: 700;
}
QPushButton#ActionButton:hover { background: #21817d; }
QTableWidget {
    background: #101a2b; alternate-background-color: #142238;
    gridline-color: #26364d; border: 1px solid #26364d;
    border-radius: 8px;
}
QHeaderView::section {
    background: #18273b; color: #b9c9dc;
    border: 0; padding: 9px; font-weight: 700;
}
QScrollArea { border: 0; }
"""


PHASES = [
    ("P1", "فهم بيئة الشبكة", "تجميع معلومات البيئة المحلية وتصنيفها بدرجة ثقة معلنة."),
    ("P2", "الأجهزة المصرح بها", "عرض الأجهزة فقط بعد اعتماد طريقة اكتشاف آمنة ونطاق واضح."),
    ("P3", "تأكيد النطاق", "تثبيت الأهداف المصرح بها وإعادة التحقق قبل كل مهمة."),
    ("P4", "الخدمات والإعدادات", "تنظيم أدلة الخدمات والإعدادات دون تجاوز النطاق."),
    ("P5", "تقييم المخاطر", "مطابقة دقيقة للأدلة مع قواعد موثوقة وتوضيح مستوى الثقة."),
    ("P6", "خطة المعالجة", "ترتيب الإصلاح والتحقق منه؛ دون تنفيذ استغلال."),
    ("P7", "تقرير HTML", "إنشاء تقرير عربي واحد يجمع النتائج والتوصيات."),
    ("P8", "ضمان الجودة", "مراجعة الأدلة والتعارضات والنتائج قبل اعتماد التقرير."),
]


def _label(text: str, object_name: str = "") -> QLabel:
    item = QLabel(text)
    item.setWordWrap(True)
    if object_name:
        item.setObjectName(object_name)
    return item


def _card(title: str, value: str, detail: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("Card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(7)
    layout.addWidget(_label(title, "Muted"))
    layout.addWidget(_label(value, "Metric"))
    layout.addWidget(_label(detail, "Muted"))
    frame.setMinimumHeight(125)
    return frame


def _page_container() -> tuple[QWidget, QVBoxLayout]:
    root = QWidget()
    layout = QVBoxLayout(root)
    layout.setContentsMargins(4, 4, 4, 4)
    layout.setSpacing(16)
    return root, layout


class MainWindow(QMainWindow):
    """Main SF window with read-only diagnostics and navigation."""

    NAV_ITEMS = [
        ("الرئيسية", 0),
        ("مراحل العمل", 1),
        ("النطاق المصرح", 2),
        ("الجلسات", 3),
        ("التقارير", 4),
        ("تشخيص النظام", 5),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SF | منصة التقييم الأمني")
        self.setMinimumSize(1080, 700)
        self.resize(1360, 820)
        self._snapshot = detect_environment()
        self._scope_entries, self._scope_error = read_scope_file()
        try:
            self.store = SFStore()
            self._storage_error = None
        except (OSError, StoreError) as exc:
            self.store = None
            self._storage_error = str(exc)
        self._nav_buttons: list[QPushButton] = []
        self._page_titles = [
            ("لوحة التحكم", "نظرة عامة على حالة SF والبيئة المحلية"),
            ("مراحل العمل", "مسار منظم من فهم البيئة إلى مراجعة التقرير"),
            ("النطاق المصرح", "فحص سياسة النطاق المحلية دون اتصال بالأهداف"),
            ("الجلسات", "إنشاء جلسات محلية وحفظ سجل العمل"),
            ("التقارير", "عرض ملفات HTML الموجودة دون فتح أو تعديل محتواها"),
            ("تشخيص النظام", "معلومات محلية عن النظام والاعتماديات المتاحة"),
        ]
        self._build_ui()
        self._refresh_views()
        self._select_page(0)

    def _build_ui(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 24, 16, 18)
        side.setSpacing(8)

        side.addWidget(_label("SF", "BrandMark"))
        side.addWidget(_label("منصة التقييم الأمني", "BrandCaption"))
        side.addSpacing(26)

        for title, index in self.NAV_ITEMS:
            button = QPushButton(title)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda checked=False, page=index: self._select_page(page))
            self._nav_buttons.append(button)
            side.addWidget(button)

        side.addStretch(1)
        side.addWidget(_label("إصدار الواجهة 0.1.0", "BrandCaption"))
        side.addWidget(_label("وضع المعاينة المحلية", "BrandCaption"))

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(24, 20, 24, 20)
        content_layout.setSpacing(16)

        top = QFrame()
        top.setObjectName("TopBar")
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(18, 12, 18, 12)

        title_block = QVBoxLayout()
        self.page_title = _label("لوحة التحكم", "PageTitle")
        self.page_subtitle = _label("", "Muted")
        title_block.addWidget(self.page_title)
        title_block.addWidget(self.page_subtitle)
        top_layout.addLayout(title_block)
        top_layout.addStretch(1)

        self.status_pill = _label("معاينة محلية فقط", "StatusPill")
        top_layout.addWidget(self.status_pill)
        refresh = QPushButton("تحديث الحالة")
        refresh.setObjectName("ActionButton")
        refresh.clicked.connect(self._refresh_all)
        top_layout.addWidget(refresh)
        content_layout.addWidget(top)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_dashboard())
        self.stack.addWidget(self._build_phases())
        self.stack.addWidget(self._build_scope())
        self.stack.addWidget(self._build_sessions())
        self.stack.addWidget(self._build_reports())
        self.stack.addWidget(self._build_diagnostics())
        content_layout.addWidget(self.stack, 1)

        root.addWidget(sidebar)
        root.addWidget(content, 1)
        self.setCentralWidget(central)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.setStyleSheet(APP_STYLE)

    def _build_dashboard(self) -> QWidget:
        page, layout = _page_container()

        hero = QFrame()
        hero.setObjectName("Hero")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(24, 23, 24, 23)
        hero_layout.setSpacing(10)
        hero_layout.addWidget(_label("مرحباً بك في SF", "PageTitle"))
        hero_layout.addWidget(_label(
            "بيئة عمل عربية منظمة لتقييم الأمان، فهم النتائج، وتحديد أولويات المعالجة.",
            "SectionTitle",
        ))
        hero_layout.addWidget(_label(
            "النسخة الحالية هي أساس الواجهة. لم يتم توصيل مراحل الفحص بالمحرك القديم بعد، "
            "ولا يتم تنفيذ أي اتصال شبكي أو فحص تلقائي عند فتح البرنامج.",
            "Muted",
        ))
        layout.addWidget(hero)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.metric_os = _card("النظام", "—", "بيانات محلية")
        self.metric_python = _card("إصدار Python", "—", "بيئة التشغيل")
        self.metric_scope = _card("النطاق المهيأ", "—", "سياسة SF المحلية")
        self.metric_sessions = _card("الجلسات المحفوظة", "—", "بيانات محلية على هذا الجهاز")
        self.metric_reports = _card("تقارير HTML", "—", "الملفات الموجودة")
        for i, frame in enumerate(
            (self.metric_os, self.metric_python, self.metric_scope,
             self.metric_sessions, self.metric_reports)
        ):
            grid.addWidget(frame, i // 2, i % 2)
        layout.addLayout(grid)

        notice = QFrame()
        notice.setObjectName("Notice")
        notice_layout = QVBoxLayout(notice)
        notice_layout.setContentsMargins(18, 14, 18, 14)
        notice_layout.addWidget(_label("مبدأ أمان أساسي", "SectionTitle"))
        notice_layout.addWidget(_label(
            "وجود عنوان داخل ملف النطاق لا يثبت وحده وجود إذن بفحصه. "
            "لن تتاح أي مهمة مستقبلية إلا بعد تأكيد الصلاحية، والتحقق من النطاق مركزياً، "
            "ومراجعة أثر المهمة وحدودها.",
            "Muted",
        ))
        layout.addWidget(notice)
        layout.addStretch(1)
        return page

    def _build_phases(self) -> QWidget:
        page, layout = _page_container()
        layout.addWidget(_label("خريطة العمل", "SectionTitle"))
        layout.addWidget(_label(
            "المراحل معروضة للتخطيط والتنظيم. حالياً لا تبدأ أي بطاقة عملية فحص.",
            "Muted",
        ))
        grid = QGridLayout()
        grid.setSpacing(12)
        for index, (code, title, detail) in enumerate(PHASES):
            frame = QFrame()
            frame.setObjectName("Card")
            box = QVBoxLayout(frame)
            box.setContentsMargins(16, 14, 16, 14)
            row = QHBoxLayout()
            row.addWidget(_label(code, "Metric"))
            row.addStretch(1)
            row.addWidget(_label("قيد التجهيز", "StatusPill"))
            box.addLayout(row)
            box.addWidget(_label(title, "SectionTitle"))
            box.addWidget(_label(detail, "Muted"))
            grid.addWidget(frame, index // 2, index % 2)
        layout.addLayout(grid)
        layout.addStretch(1)
        return page

    def _build_scope(self) -> QWidget:
        page, layout = _page_container()
        layout.addWidget(_label("ملف النطاق الحالي", "SectionTitle"))
        self.scope_path_label = _label(
            f"المسار: {PROJECT_ROOT / 'config' / 'scope.txt'}", "Muted"
        )
        layout.addWidget(self.scope_path_label)
        self.scope_table = QTableWidget(0, 5)
        self.scope_table.setHorizontalHeaderLabels(
            ["العنصر", "النوع", "الصيغة", "سياسة SF", "سبب القرار"]
        )
        self.scope_table.setAlternatingRowColors(True)
        self.scope_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.scope_table.horizontalHeader().setStretchLastSection(True)
        self.scope_table.horizontalHeader().setDefaultSectionSize(170)
        layout.addWidget(self.scope_table, 1)

        self.scope_summary = _label("", "Muted")
        layout.addWidget(self.scope_summary)
        notice = QFrame()
        notice.setObjectName("Notice")
        note_layout = QVBoxLayout(notice)
        note_layout.setContentsMargins(16, 12, 16, 12)
        note_layout.addWidget(_label(
            "تنبيه: التحقق هنا لغوي/شكلي فقط. لا يتم الاتصال بالعناوين أو اختبارها، "
            "ولا يعني ظهورها في القائمة أنها مصرح بها تلقائياً.",
            "Muted",
        ))
        layout.addWidget(notice)
        return page

    def _build_sessions(self) -> QWidget:
        page, layout = _page_container()
        header = QHBoxLayout()
        header.addWidget(_label("جلسات SF المحلية", "SectionTitle"))
        header.addStretch(1)
        create_button = QPushButton("إنشاء جلسة جديدة")
        create_button.setObjectName("ActionButton")
        create_button.clicked.connect(self._create_session)
        header.addWidget(create_button)
        refresh_button = QPushButton("تحديث")
        refresh_button.clicked.connect(self._refresh_sessions_table)
        header.addWidget(refresh_button)
        layout.addLayout(header)
        layout.addWidget(_label(
            "تُحفظ بيانات الجلسات على هذا الجهاز فقط. لا يبدأ إنشاء الجلسة أي فحص أو اتصال.",
            "Muted",
        ))
        self.sessions_table = QTableWidget(0, 4)
        self.sessions_table.setHorizontalHeaderLabels(
            ["معرّف الجلسة", "الاسم", "الحالة", "آخر تحديث"]
        )
        self.sessions_table.setAlternatingRowColors(True)
        self.sessions_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sessions_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.sessions_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.sessions_table.itemSelectionChanged.connect(self._on_session_selection_changed)
        self.sessions_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.sessions_table, 1)

        actions = QHBoxLayout()
        self.export_report_button = QPushButton("إنشاء / تحديث تقرير HTML")
        self.export_report_button.setObjectName("ActionButton")
        self.export_report_button.setEnabled(False)
        self.export_report_button.clicked.connect(self._export_selected_report)
        actions.addWidget(self.export_report_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.sessions_status = _label("", "Muted")
        layout.addWidget(self.sessions_status)
        return page

    def _create_session(self) -> None:
        if self.store is None:
            QMessageBox.warning(
                self, "تعذر إنشاء الجلسة",
                f"مخزن SF المحلي غير متاح: {self._storage_error or 'خطأ غير معروف'}",
            )
            return
        name, accepted = QInputDialog.getText(
            self, "جلسة جديدة", "اسم الجلسة:"
        )
        if not accepted:
            return
        try:
            record = self.store.create_session(name)
            self._refresh_sessions_table()
            self.sessions_status.setText(
                f"تم إنشاء الجلسة المحلية: {record['id']}"
            )
        except (ValueError, StoreError, OSError) as exc:
            QMessageBox.warning(self, "تعذر إنشاء الجلسة", str(exc))

    def _refresh_sessions_table(self) -> None:
        if not hasattr(self, "sessions_table"):
            return
        self.sessions_table.setRowCount(0)
        if self.store is None:
            self.sessions_status.setText(
                f"مخزن الجلسات غير متاح: {self._storage_error or 'غير معروف'}"
            )
            return
        try:
            sessions = self.store.list_sessions(limit=50)
        except (StoreError, OSError) as exc:
            self.sessions_status.setText(f"تعذر قراءة الجلسات: {exc}")
            return
        for session in sessions:
            row = self.sessions_table.rowCount()
            self.sessions_table.insertRow(row)
            values = (
                session["id"],
                session["name"],
                "مفتوحة" if session["status"] == "open" else "مغلقة",
                session["updated_at"],
            )
            for column, value in enumerate(values):
                self.sessions_table.setItem(row, column, QTableWidgetItem(str(value)))
        self.sessions_status.setText(
            f"عدد الجلسات المحفوظة: {len(sessions)}"
        )
        self.export_report_button.setEnabled(False)

    def _on_session_selection_changed(self) -> None:
        row = self.sessions_table.currentRow()
        item = self.sessions_table.item(row, 0) if row >= 0 else None
        session_id = item.text() if item else ""
        self.export_report_button.setEnabled(bool(session_id and self.store))
        if not session_id or self.store is None:
            return
        try:
            session = self.store.get_session(session_id)
            evidence_count = len(self.store.list_evidence(session_id))
            if session:
                self.sessions_status.setText(
                    f"المحدد: {session['name']} | "
                    f"الأدلة المسجلة: {evidence_count} | "
                    f"الحالة: {'مفتوحة' if session['status'] == 'open' else 'مغلقة'}"
                )
        except (StoreError, OSError) as exc:
            self.sessions_status.setText(f"تعذر قراءة تفاصيل الجلسة: {exc}")

    def _export_selected_report(self) -> None:
        row = self.sessions_table.currentRow()
        item = self.sessions_table.item(row, 0) if row >= 0 else None
        if item is None or self.store is None:
            QMessageBox.information(self, "اختر جلسة", "حدد جلسة من الجدول أولاً.")
            return
        try:
            path = generate_session_report(self.store, item.text())
            self._refresh_reports_table()
            self.metric_reports.findChild(QLabel, "Metric").setText(
                str(len(list_html_reports()))
            )
            self.sessions_status.setText(f"تم إنشاء التقرير: {path}")
            QMessageBox.information(
                self, "تقرير SF جاهز",
                f"تم إنشاء تقرير HTML أو تحديث التقرير السابق للجلسة نفسها.\n\n{path}",
            )
        except (ReportError, OSError, StoreError) as exc:
            QMessageBox.warning(self, "تعذر إنشاء التقرير", str(exc))

    def _build_reports(self) -> QWidget:
        page, layout = _page_container()
        layout.addWidget(_label("مخرجات التقارير", "SectionTitle"))
        layout.addWidget(_label(
            "يعرض SF تقارير الجلسات بصيغة HTML. إعادة التوليد تحدث تقرير الجلسة نفسه بدلاً من إنشاء نسخ متكررة.",
            "Muted",
        ))
        self.report_table = QTableWidget(0, 3)
        self.report_table.setHorizontalHeaderLabels(["اسم الملف", "الحجم", "آخر تعديل"])
        self.report_table.setAlternatingRowColors(True)
        self.report_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.report_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.report_table, 1)
        self.report_empty = _label("", "Muted")
        layout.addWidget(self.report_empty)
        return page

    def _build_diagnostics(self) -> QWidget:
        page, layout = _page_container()
        layout.addWidget(_label("تشخيص البيئة المحلية", "SectionTitle"))
        layout.addWidget(_label(
            "قراءة معلومات النظام ووجود البرامج في PATH فقط؛ لا يتم تشغيلها.",
            "Muted",
        ))
        self.diagnostics_table = QTableWidget(0, 3)
        self.diagnostics_table.setHorizontalHeaderLabels(["البند", "القيمة", "الحالة"])
        self.diagnostics_table.setAlternatingRowColors(True)
        self.diagnostics_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.diagnostics_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.diagnostics_table, 1)
        return page

    def _select_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        title, subtitle = self._page_titles[index]
        self.page_title.setText(title)
        self.page_subtitle.setText(subtitle)
        for position, button in enumerate(self._nav_buttons):
            button.setChecked(position == index)

    def _refresh_all(self) -> None:
        self._snapshot = detect_environment()
        self._scope_entries, self._scope_error = read_scope_file()
        self._refresh_views()

    def _refresh_views(self) -> None:
        snapshot = self._snapshot
        self.metric_os.findChild(QLabel, "Metric").setText(snapshot.distribution)
        self.metric_python.findChild(QLabel, "Metric").setText(snapshot.python_version)
        allowed_count = sum(validate_scope_entry(entry.value).allowed for entry in self._scope_entries)
        denied_count = len(self._scope_entries) - allowed_count
        self.metric_scope.findChild(QLabel, "Metric").setText(
            f"{allowed_count} مسموح / {denied_count} مرفوض"
        )
        try:
            session_count = len(self.store.list_sessions(limit=1000)) if self.store else "غير متاح"
        except (StoreError, OSError) as exc:
            session_count = "خطأ"
            self._storage_error = str(exc)
        self.metric_sessions.findChild(QLabel, "Metric").setText(str(session_count))
        self.metric_reports.findChild(QLabel, "Metric").setText(str(len(list_html_reports())))
        self._refresh_scope_table()
        self._refresh_sessions_table()
        self._refresh_reports_table()
        self._refresh_diagnostics_table()

    def _refresh_scope_table(self) -> None:
        table = self.scope_table
        table.setRowCount(0)
        for entry in self._scope_entries:
            row = table.rowCount()
            table.insertRow(row)
            decision = validate_scope_entry(entry.value)
            values = (
                entry.value,
                entry.kind,
                "صالح" if entry.valid else "غير صالح",
                "مسموح محلياً" if decision.allowed else "مرفوض",
                decision.reason,
            )
            for column, value in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(value))
        if self._scope_error:
            self.scope_summary.setText(f"تعذر قراءة الملف: {self._scope_error}")
        else:
            allowed = sum(validate_scope_entry(item.value).allowed for item in self._scope_entries)
            denied = len(self._scope_entries) - allowed
            self.scope_summary.setText(
                f"عدد الإدخالات: {len(self._scope_entries)} | "
                f"مسموح بسياسة SF: {allowed} | مرفوض: {denied}"
            )

    def _refresh_reports_table(self) -> None:
        reports = list_html_reports()
        self.report_table.setRowCount(0)
        for report in reports:
            row = self.report_table.rowCount()
            self.report_table.insertRow(row)
            stat = report.stat()
            values = (
                report.name,
                f"{stat.st_size / 1024:.1f} KB",
                __import__("datetime").datetime.fromtimestamp(
                    stat.st_mtime
                ).strftime("%Y-%m-%d %H:%M"),
            )
            for column, value in enumerate(values):
                self.report_table.setItem(row, column, QTableWidgetItem(value))
        self.report_empty.setText(
            "لا توجد تقارير HTML محفوظة حالياً."
            if not reports else f"تم العثور على {len(reports)} تقرير HTML."
        )

    def _refresh_diagnostics_table(self) -> None:
        snapshot = self._snapshot
        rows = [
            ("النظام", snapshot.distribution, "تمت القراءة"),
            ("الإصدار", snapshot.distribution_version, "تمت القراءة"),
            ("Python", snapshot.python_version, "متاح"),
            ("المعمارية", snapshot.architecture, "تمت القراءة"),
            ("صلاحيات المستخدم", "root" if snapshot.is_root else "مستخدم عادي",
             "يُفضّل التشغيل كمستخدم عادي"),
        ]
        for name, present in snapshot.tools.items():
            rows.append((name, "موجود" if present else "غير موجود",
                         "تم فحص PATH فقط"))
        self.diagnostics_table.setRowCount(0)
        for values in rows:
            row = self.diagnostics_table.rowCount()
            self.diagnostics_table.insertRow(row)
            for column, value in enumerate(values):
                self.diagnostics_table.setItem(row, column, QTableWidgetItem(value))
