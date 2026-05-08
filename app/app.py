"""
ui/app.py
=========
Phantom Recon — Main Application UI

Ultra-dark professional recon interface:
  - Target input with scan profile selector
  - Module selection (DNS, Ports, SSL, Web, GEO, Subdomains, Dorks)
  - Real-time findings table with severity coloring
  - Progress per module
  - Session history panel
  - Node graph visualization
  - Export JSON/TXT
"""

import os, sys, json, webbrowser
from typing import Optional, List, Dict
from datetime import datetime

from PyQt6.QtCore    import Qt, QTimer, QSize, QPoint, QThread, pyqtSignal, QRect
from PyQt6.QtGui     import (QColor, QFont, QPainter, QPen, QBrush,
                              QKeySequence, QShortcut, QClipboard, QIcon,
                              QLinearGradient, QPalette)
from PyQt6.QtWidgets import (
    QWidget, QApplication, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox, QScrollArea,
    QFrame, QSizePolicy, QFileDialog, QMessageBox, QSplitter,
    QStackedWidget, QToolButton, QCheckBox, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QGraphicsDropShadowEffect, QListWidget, QListWidgetItem,
    QTabWidget, QGroupBox, QDialog
)

from core.scanner  import (DNSScanner, PortScanner, WHOISScanner, SSLScanner,
                            WebScanner, GeoScanner, SubdomainScanner,
                            DorksGenerator, Finding)
from core.database import ScanDatabase


# ── Palette ───────────────────────────────────────────────────────────────────
BG         = "#07070e"
BG2        = "#0b0b16"
BG3        = "#0f0f1c"
SURFACE    = "#121220"
SURFACE2   = "#181828"
BORDER     = "#1c1c30"
BORDER2    = "#222236"
ACCENT     = "#7c6af7"
ACCENT2    = "#5b4fd4"
ACCENT_DIM = "#1e1a40"
RED        = "#e05577"
RED_DIM    = "#2a0a14"
GREEN      = "#3dd68c"
GREEN_DIM  = "#0a2a1a"
YELLOW     = "#e8c46a"
YELLOW_DIM = "#2a1e04"
CYAN       = "#3ecfcf"
ORANGE     = "#f08040"
FG         = "#c8c8d4"
FG_MED     = "#666680"
FG_DIM     = "#333348"

SEVERITY_COLORS = {
    "info":     (CYAN,   "#0a1e2a"),
    "low":      (YELLOW, "#2a1e04"),
    "medium":   (ORANGE, "#2a1408"),
    "high":     (RED,    "#2a0a14"),
    "critical": ("#ff0044", "#1a0010"),
}

CATEGORY_ICONS = {
    "DNS":   "🌐", "PORT": "🚪", "WHOIS": "📋",
    "SSL":   "🔒", "WEB":  "🕸",  "GEO":   "📍",
    "SUB":   "🔍", "DORK": "🎯",
}

FONT = "IBM Plex Mono, Fira Code, Consolas, monospace"
FONT_UI = "Segoe UI, SF Pro Display, system-ui, sans-serif"


def qlabel(text, size=12, color=FG, bold=False, font=FONT_UI) -> QLabel:
    l = QLabel(text)
    w = 700 if bold else 400
    l.setStyleSheet(f"color:{color}; font-size:{size}px; font-weight:{w}; font-family:{font};")
    return l


def qbtn(text, accent=False, danger=False, small=False) -> QPushButton:
    b = QPushButton(text)
    h = 28 if small else 34
    b.setFixedHeight(h)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    if accent:
        b.setStyleSheet(f"""
            QPushButton{{background:{ACCENT}; color:white; border:none;
                border-radius:5px; font-size:12px; font-family:{FONT_UI};
                padding:0 14px; font-weight:600;}}
            QPushButton:hover{{background:{ACCENT2};}}
            QPushButton:disabled{{background:{ACCENT_DIM}; color:{FG_MED};}}
        """)
    elif danger:
        b.setStyleSheet(f"""
            QPushButton{{background:{RED_DIM}; color:{RED}; border:1px solid #3a1020;
                border-radius:5px; font-size:12px; font-family:{FONT_UI}; padding:0 14px;}}
            QPushButton:hover{{background:#3a1020;}}
        """)
    else:
        b.setStyleSheet(f"""
            QPushButton{{background:{SURFACE2}; color:{FG_MED}; border:1px solid {BORDER2};
                border-radius:5px; font-size:12px; font-family:{FONT_UI}; padding:0 14px;}}
            QPushButton:hover{{background:{BORDER2}; color:{FG};}}
            QPushButton:disabled{{opacity:0.4;}}
        """)
    return b


# ─────────────────────────────────────────────────────────────────────────────
# Title Bar
# ─────────────────────────────────────────────────────────────────────────────

class TitleBar(QWidget):
    def __init__(self, win):
        super().__init__(win)
        self._win = win
        self._drag = None
        self.setFixedHeight(44)
        self.setStyleSheet(f"background:{BG}; border-bottom:1px solid {BORDER};")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 0, 8, 0)
        lay.setSpacing(10)

        logo = QLabel("◈")
        logo.setStyleSheet(f"color:{ACCENT}; font-size:20px; font-family:{FONT};")
        lay.addWidget(logo)

        t1 = QLabel("PHANTOM")
        t1.setStyleSheet(f"color:{FG}; font-size:12px; font-weight:800; letter-spacing:3px; font-family:{FONT};")
        lay.addWidget(t1)

        t2 = QLabel("RECON")
        t2.setStyleSheet(f"color:{ACCENT}; font-size:12px; font-weight:800; letter-spacing:3px; font-family:{FONT};")
        lay.addWidget(t2)

        lay.addSpacing(16)
        self._target_badge = QLabel("")
        self._target_badge.setStyleSheet(f"""
            color:{CYAN}; font-size:11px; font-family:{FONT};
            background:{SURFACE}; border:1px solid {BORDER2};
            border-radius:4px; padding:1px 8px;
        """)
        self._target_badge.hide()
        lay.addWidget(self._target_badge)

        lay.addStretch()

        self._status = QLabel("جاهز")
        self._status.setStyleSheet(f"color:{FG_DIM}; font-size:10px; font-family:{FONT_UI};")
        lay.addWidget(self._status)
        lay.addSpacing(16)

        for sym, cb, name in [("─", win.showMinimized, "min"),
                               ("□", self._toggle, "max"),
                               ("✕", win.close, "cls")]:
            b = QPushButton(sym)
            b.setFixedSize(34, 26)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            cls_style = f"QPushButton{{background:transparent;color:{FG_DIM};border:none;font-size:11px;}}QPushButton:hover{{background:#c0392b;color:white;}}"
            nor_style = f"QPushButton{{background:transparent;color:{FG_DIM};border:none;font-size:11px;}}QPushButton:hover{{background:{SURFACE2};color:{FG};}}"
            b.setStyleSheet(cls_style if name == "cls" else nor_style)
            b.clicked.connect(cb)
            lay.addWidget(b)

    def _toggle(self):
        self._win.showNormal() if self._win.isMaximized() else self._win.showMaximized()

    def set_target(self, t: str):
        self._target_badge.setText(f"  {t}  ")
        self._target_badge.show()

    def set_status(self, s: str, color: str = FG_DIM):
        self._status.setText(s)
        self._status.setStyleSheet(f"color:{color}; font-size:10px; font-family:{FONT_UI};")

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint() - self._win.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if e.buttons() & Qt.MouseButton.LeftButton and self._drag:
            self._win.move(e.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, e): self._drag = None
    def mouseDoubleClickEvent(self, e): self._toggle()


# ─────────────────────────────────────────────────────────────────────────────
# Module Toggle Button
# ─────────────────────────────────────────────────────────────────────────────

class ModuleBtn(QWidget):
    toggled = pyqtSignal(str, bool)

    def __init__(self, key: str, icon: str, label: str, default: bool = True):
        super().__init__()
        self.key     = key
        self._active = default
        self.setFixedHeight(36)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 0, 10, 0)
        lay.setSpacing(6)

        self._icon  = QLabel(icon)
        self._icon.setStyleSheet("font-size:14px;")
        self._label = QLabel(label)
        self._label.setStyleSheet(f"font-size:11px; font-family:{FONT_UI};")
        self._dot   = QLabel("●")
        self._dot.setFixedWidth(10)
        self._dot.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lay.addWidget(self._icon)
        lay.addWidget(self._label, stretch=1)
        lay.addWidget(self._dot)

        self._update()

    def _update(self):
        if self._active:
            self.setStyleSheet(f"background:{ACCENT_DIM}; border:1px solid {ACCENT}44; border-radius:6px;")
            self._label.setStyleSheet(f"color:{FG}; font-size:11px; font-family:{FONT_UI};")
            self._dot.setStyleSheet(f"color:{ACCENT}; font-size:8px;")
        else:
            self.setStyleSheet(f"background:{SURFACE}; border:1px solid {BORDER}; border-radius:6px;")
            self._label.setStyleSheet(f"color:{FG_DIM}; font-size:11px; font-family:{FONT_UI};")
            self._dot.setStyleSheet(f"color:{FG_DIM}; font-size:8px;")

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._active = not self._active
            self._update()
            self.toggled.emit(self.key, self._active)

    def set_active(self, v: bool):
        self._active = v
        self._update()

    def is_active(self) -> bool:
        return self._active

    def set_running(self, running: bool):
        if running:
            self.setStyleSheet(f"background:{GREEN_DIM}; border:1px solid {GREEN}44; border-radius:6px;")
            self._dot.setStyleSheet(f"color:{GREEN}; font-size:8px;")

    def set_done(self):
        self.setStyleSheet(f"background:{SURFACE}; border:1px solid {GREEN}44; border-radius:6px;")
        self._dot.setStyleSheet(f"color:{GREEN}; font-size:8px;")
        self._dot.setText("✓")


# ─────────────────────────────────────────────────────────────────────────────
# Findings Table
# ─────────────────────────────────────────────────────────────────────────────

class FindingsTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 5)
        self.setHorizontalHeaderLabels(["", "الوقت", "الفئة", "المفتاح", "القيمة"])
        self.verticalHeader().hide()
        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setWordWrap(True)

        hdr = self.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.setColumnWidth(0, 14)
        self.setColumnWidth(1, 64)
        self.setColumnWidth(2, 80)

        self.setStyleSheet(f"""
            QTableWidget {{
                background:{BG2}; color:{FG}; border:none;
                font-size:12px; font-family:{FONT_UI};
                gridline-color:{BORDER};
                selection-background-color:{ACCENT_DIM};
            }}
            QHeaderView::section {{
                background:{BG}; color:{FG_MED};
                border:none; border-bottom:1px solid {BORDER};
                padding:6px 8px; font-size:10px;
                font-weight:700; letter-spacing:1px;
                font-family:{FONT_UI};
            }}
            QTableWidget::item {{
                padding:4px 8px; border-bottom:1px solid {BORDER};
            }}
            QScrollBar:vertical {{
                background:{BG2}; width:5px; border:none;
            }}
            QScrollBar::handle:vertical {{
                background:{BORDER2}; border-radius:2px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
        """)

        self._count = 0
        self._filters = set()  # Active category filters

    def add_finding(self, f: Finding):
        row = self.rowCount()
        self.insertRow(row)
        self.setRowHeight(row, 28)

        color, bg_color = SEVERITY_COLORS.get(f.severity, (FG_MED, BG2))

        # Severity dot
        dot = QTableWidgetItem("●")
        dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        dot.setForeground(QColor(color))
        self.setItem(row, 0, dot)

        # Time
        ts = QTableWidgetItem(f.timestamp)
        ts.setForeground(QColor(FG_DIM))
        self.setItem(row, 1, ts)

        # Category
        icon = CATEGORY_ICONS.get(f.category, "◈")
        cat = QTableWidgetItem(f"{icon} {f.category}")
        cat.setForeground(QColor(color))
        self.setItem(row, 2, cat)

        # Key
        key = QTableWidgetItem(f.key)
        key.setForeground(QColor(FG_MED))
        self.setItem(row, 3, key)

        # Value
        val = QTableWidgetItem(f.value)
        val.setForeground(QColor(FG))
        if f.severity in ("critical", "high"):
            val.setBackground(QColor(bg_color))
        self.setItem(row, 4, val)

        self._count += 1
        self.scrollToBottom()

    def clear_findings(self):
        self.setRowCount(0)
        self._count = 0

    def filter_by_category(self, category: str, show: bool):
        if show:
            self._filters.discard(category)
        else:
            self._filters.add(category)
        for row in range(self.rowCount()):
            cat_item = self.item(row, 2)
            if cat_item:
                cat = cat_item.text().split()[-1]
                self.setRowHidden(row, cat in self._filters)

    def filter_by_severity(self, severity: str):
        for row in range(self.rowCount()):
            dot = self.item(row, 0)
            if dot:
                sev_map = {
                    QColor(CYAN).name():     "info",
                    QColor(YELLOW).name():   "low",
                    QColor(ORANGE).name():   "medium",
                    QColor(RED).name():      "high",
                    QColor("#ff0044").name(): "critical",
                }
                # Show all if "all", otherwise filter
                if severity == "all":
                    self.setRowHidden(row, False)

    def export_text(self) -> str:
        lines = []
        for row in range(self.rowCount()):
            parts = []
            for col in range(1, 5):
                item = self.item(row, col)
                if item:
                    parts.append(item.text())
            lines.append("  |  ".join(parts))
        return "\n".join(lines)

    def count(self) -> int:
        return self._count


# ─────────────────────────────────────────────────────────────────────────────
# Progress Panel
# ─────────────────────────────────────────────────────────────────────────────

class ModuleProgress(QWidget):
    def __init__(self, key: str, icon: str, label: str):
        super().__init__()
        self.key = key
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.setSpacing(8)

        lbl = QLabel(f"{icon} {label}")
        lbl.setFixedWidth(120)
        lbl.setStyleSheet(f"color:{FG_MED}; font-size:11px; font-family:{FONT_UI};")
        lay.addWidget(lbl)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setFixedHeight(6)
        self._bar.setStyleSheet(f"""
            QProgressBar {{
                background:{SURFACE2}; border:none; border-radius:3px;
            }}
            QProgressBar::chunk {{
                background:{ACCENT}; border-radius:3px;
            }}
        """)
        lay.addWidget(self._bar, stretch=1)

        self._msg = QLabel("")
        self._msg.setFixedWidth(180)
        self._msg.setStyleSheet(f"color:{FG_DIM}; font-size:10px; font-family:{FONT_UI};")
        lay.addWidget(self._msg)

        self._status = QLabel("○")
        self._status.setFixedWidth(18)
        self._status.setStyleSheet(f"color:{FG_DIM}; font-size:10px;")
        lay.addWidget(self._status)

    def update_progress(self, pct: int, msg: str):
        self._bar.setValue(pct)
        self._msg.setText(msg[:35])
        if pct > 0:
            self._status.setText("◌")
            self._status.setStyleSheet(f"color:{YELLOW}; font-size:10px;")
            self._bar.setStyleSheet(f"""
                QProgressBar {{background:{SURFACE2}; border:none; border-radius:3px;}}
                QProgressBar::chunk {{background:{YELLOW}; border-radius:3px;}}
            """)

    def set_done(self):
        self._bar.setValue(100)
        self._status.setText("✓")
        self._status.setStyleSheet(f"color:{GREEN}; font-size:10px;")
        self._bar.setStyleSheet(f"""
            QProgressBar {{background:{SURFACE2}; border:none; border-radius:3px;}}
            QProgressBar::chunk {{background:{GREEN}; border-radius:3px;}}
        """)

    def set_error(self, msg: str):
        self._msg.setText(msg[:35])
        self._msg.setStyleSheet(f"color:{RED}; font-size:10px; font-family:{FONT_UI};")
        self._status.setText("✕")
        self._status.setStyleSheet(f"color:{RED}; font-size:10px;")

    def reset(self):
        self._bar.setValue(0)
        self._msg.setText("")
        self._status.setText("○")
        self._status.setStyleSheet(f"color:{FG_DIM}; font-size:10px;")
        self._bar.setStyleSheet(f"""
            QProgressBar {{background:{SURFACE2}; border:none; border-radius:3px;}}
            QProgressBar::chunk {{background:{ACCENT}; border-radius:3px;}}
        """)


# ─────────────────────────────────────────────────────────────────────────────
# Dorks Panel
# ─────────────────────────────────────────────────────────────────────────────

class DorksPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"background:{BG2};")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(8)

        hdr = QHBoxLayout()
        hdr.addWidget(qlabel("🎯  Google Dorks", 13, FG, True))
        hdr.addStretch()
        copy_btn = qbtn("نسخ الكل", small=True)
        copy_btn.clicked.connect(self._copy_all)
        hdr.addWidget(copy_btn)
        lay.addLayout(hdr)

        self._list = QListWidget()
        self._list.setStyleSheet(f"""
            QListWidget {{
                background:{SURFACE}; color:{FG}; border:1px solid {BORDER2};
                border-radius:6px; font-size:12px; font-family:{FONT};
            }}
            QListWidget::item {{
                padding:6px 10px; border-bottom:1px solid {BORDER};
            }}
            QListWidget::item:selected {{
                background:{ACCENT_DIM}; color:{ACCENT};
            }}
            QScrollBar:vertical {{
                background:{SURFACE}; width:4px; border:none;
            }}
            QScrollBar::handle:vertical {{
                background:{BORDER2}; border-radius:2px;
            }}
        """)
        self._list.itemDoubleClicked.connect(self._open_dork)
        lay.addWidget(self._list)

        note = qlabel("انقر مرتين لفتح في المتصفح", 10, FG_DIM)
        lay.addWidget(note)

    def load_dorks(self, domain: str):
        self._list.clear()
        dorks = DorksGenerator.generate(domain)
        for query, desc in dorks:
            item = QListWidgetItem(f"  {desc}\n  {query}")
            item.setData(Qt.ItemDataRole.UserRole, query)
            self._list.addItem(item)

    def _open_dork(self, item: QListWidgetItem):
        query = item.data(Qt.ItemDataRole.UserRole)
        if query:
            url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
            webbrowser.open(url)

    def _copy_all(self):
        dorks = []
        for i in range(self._list.count()):
            item = self._list.item(i)
            q = item.data(Qt.ItemDataRole.UserRole)
            if q:
                dorks.append(q)
        QApplication.clipboard().setText("\n".join(dorks))


# ─────────────────────────────────────────────────────────────────────────────
# Session History Panel
# ─────────────────────────────────────────────────────────────────────────────

class HistoryPanel(QWidget):
    session_selected = pyqtSignal(int)

    def __init__(self, db: ScanDatabase):
        super().__init__()
        self._db = db
        self.setFixedWidth(260)
        self.setStyleSheet(f"background:{BG2}; border-left:1px solid {BORDER};")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Header
        hdr = QWidget()
        hdr.setFixedHeight(44)
        hdr.setStyleSheet(f"background:{BG}; border-bottom:1px solid {BORDER};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(12, 0, 12, 0)
        hl.addWidget(qlabel("📁  السجل", 11, FG_MED, True))
        hl.addStretch()
        ref = QPushButton("↺")
        ref.setFixedSize(26, 26)
        ref.setStyleSheet(f"background:transparent; color:{FG_MED}; border:none; font-size:14px;")
        ref.clicked.connect(self.refresh)
        hl.addWidget(ref)
        lay.addWidget(hdr)

        # List
        self._list = QListWidget()
        self._list.setStyleSheet(f"""
            QListWidget {{
                background:{BG2}; border:none; color:{FG};
                font-size:11px; font-family:{FONT_UI};
            }}
            QListWidget::item {{
                padding:8px 12px; border-bottom:1px solid {BORDER};
            }}
            QListWidget::item:selected {{ background:{ACCENT_DIM}; color:{ACCENT}; }}
            QListWidget::item:hover:!selected {{ background:{SURFACE}; }}
            QScrollBar:vertical {{background:{BG2}; width:4px; border:none;}}
            QScrollBar::handle:vertical {{background:{BORDER2}; border-radius:2px;}}
        """)
        self._list.itemDoubleClicked.connect(self._on_select)
        lay.addWidget(self._list, stretch=1)

        # Export button
        export_btn = qbtn("📤  تصدير الجلسة")
        export_btn.setStyleSheet(export_btn.styleSheet() + "margin:8px;")
        export_btn.clicked.connect(self._export_selected)
        lay.addWidget(export_btn)

        self.refresh()

    def refresh(self):
        self._list.clear()
        for row in self._db.list_sessions():
            target  = row["target"]
            started = row["started_at"] or ""
            status  = row["status"]
            count   = self._db.count_findings(row["id"])
            icon    = "✓" if status == "completed" else "⟳"
            item = QListWidgetItem(f"{icon}  {target}\n   {started[:16]}  ·  {count} نتيجة")
            item.setData(Qt.ItemDataRole.UserRole, row["id"])
            self._list.addItem(item)

    def _on_select(self, item: QListWidgetItem):
        sid = item.data(Qt.ItemDataRole.UserRole)
        if sid:
            self.session_selected.emit(sid)

    def _export_selected(self):
        item = self._list.currentItem()
        if not item:
            return
        sid  = item.data(Qt.ItemDataRole.UserRole)
        path, _ = QFileDialog.getSaveFileName(
            self, "تصدير JSON", f"scan_{sid}.json", "JSON (*.json)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._db.export_json(sid))


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────

class PhantomRecon(QWidget):

    MODULES = [
        ("DNS",   "🌐", "DNS Records",    True),
        ("PORT",  "🚪", "Port Scanner",   True),
        ("WHOIS", "📋", "WHOIS",          True),
        ("SSL",   "🔒", "SSL/TLS",        True),
        ("WEB",   "🕸",  "Web Analysis",   True),
        ("GEO",   "📍", "GeoIP",          True),
        ("SUB",   "🔍", "Subdomains",     False),
    ]

    def __init__(self):
        super().__init__()
        self._db           = ScanDatabase()
        self._scanners     = []
        self._session_id   = None
        self._running      = False
        self._finding_count = 0
        self._modules_done = 0
        self._modules_total = 0

        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setMinimumSize(1200, 750)
        self.resize(1500, 900)
        self.setStyleSheet(f"background:{BG}; color:{FG};")

        self._build_ui()

    # ─────────────────────────────────────────────
    # UI Build
    # ─────────────────────────────────────────────

    def _build_ui(self):
        main = QVBoxLayout(self)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        # Title bar
        self._title_bar = TitleBar(self)
        main.addWidget(self._title_bar)

        # Body
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # ── Left sidebar ──────────────────────────
        body.addWidget(self._build_left_panel())

        # ── Center main area ──────────────────────
        body.addWidget(self._build_center(), stretch=1)

        # ── Right history ─────────────────────────
        self._history = HistoryPanel(self._db)
        self._history.session_selected.connect(self._load_session)
        body.addWidget(self._history)

        body_w = QWidget()
        body_w.setLayout(body)
        main.addWidget(body_w, stretch=1)

        # Status bar
        main.addWidget(self._build_status_bar())

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        panel.setFixedWidth(220)
        panel.setStyleSheet(f"background:{BG2}; border-right:1px solid {BORDER};")
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(10, 12, 10, 12)
        lay.setSpacing(6)

        # Target input
        lay.addWidget(qlabel("الهدف", 10, FG_MED, True))
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("example.com  /  192.168.1.1")
        self._target_input.setFixedHeight(36)
        self._target_input.setStyleSheet(f"""
            QLineEdit {{
                background:{SURFACE}; color:{FG}; border:1px solid {BORDER2};
                border-radius:6px; padding:0 10px;
                font-size:12px; font-family:{FONT};
            }}
            QLineEdit:focus {{ border-color:{ACCENT}; }}
        """)
        self._target_input.returnPressed.connect(self._start_scan)
        lay.addWidget(self._target_input)

        # Scan profile
        lay.addSpacing(8)
        lay.addWidget(qlabel("ملف المسح", 10, FG_MED, True))
        self._profile_combo = QComboBox()
        self._profile_combo.addItems(["Quick — سريع", "Deep — شامل", "Stealth — خفي"])
        self._profile_combo.setFixedHeight(32)
        self._profile_combo.setStyleSheet(f"""
            QComboBox {{
                background:{SURFACE}; color:{FG}; border:1px solid {BORDER2};
                border-radius:6px; padding:0 10px; font-size:11px; font-family:{FONT_UI};
            }}
            QComboBox::drop-down {{ border:none; width:20px; }}
            QComboBox QAbstractItemView {{
                background:{SURFACE2}; color:{FG}; border:1px solid {BORDER2};
                selection-background-color:{ACCENT_DIM};
            }}
        """)
        lay.addWidget(self._profile_combo)

        # Modules
        lay.addSpacing(10)
        lay.addWidget(qlabel("الوحدات", 10, FG_MED, True))

        self._module_btns: Dict[str, ModuleBtn] = {}
        for key, icon, label, default in self.MODULES:
            btn = ModuleBtn(key, icon, label, default)
            btn.toggled.connect(self._on_module_toggled)
            self._module_btns[key] = btn
            lay.addWidget(btn)

        lay.addSpacing(4)

        # Port range
        lay.addWidget(qlabel("نطاق المنافذ", 10, FG_MED, True))
        self._port_combo = QComboBox()
        self._port_combo.addItems(["Common (شائع)", "Top 1000", "Full (1-65535)"])
        self._port_combo.setFixedHeight(30)
        self._port_combo.setStyleSheet(self._profile_combo.styleSheet())
        lay.addWidget(self._port_combo)

        lay.addStretch()

        # Scan button
        self._scan_btn = QPushButton("◈  بدء المسح")
        self._scan_btn.setFixedHeight(40)
        self._scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._scan_btn.setStyleSheet(f"""
            QPushButton {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {ACCENT}, stop:1 {ACCENT2});
                color:white; border:none; border-radius:8px;
                font-size:13px; font-weight:700; font-family:{FONT_UI};
                letter-spacing:1px;
            }}
            QPushButton:hover {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #9080ff, stop:1 {ACCENT});
            }}
            QPushButton:disabled {{ background:{ACCENT_DIM}; color:{FG_MED}; }}
        """)
        self._scan_btn.clicked.connect(self._start_scan)
        lay.addWidget(self._scan_btn)

        # Stop button
        self._stop_btn = qbtn("■  إيقاف", danger=True)
        self._stop_btn.setFixedHeight(34)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)
        lay.addWidget(self._stop_btn)

        return panel

    def _build_center(self) -> QWidget:
        center = QWidget()
        lay = QVBoxLayout(center)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Progress area ──────────────────────────
        prog_widget = QWidget()
        prog_widget.setFixedHeight(180)
        prog_widget.setStyleSheet(f"background:{BG2}; border-bottom:1px solid {BORDER};")
        pgl = QVBoxLayout(prog_widget)
        pgl.setContentsMargins(20, 10, 20, 10)
        pgl.setSpacing(4)

        ph = QHBoxLayout()
        ph.addWidget(qlabel("تقدم المسح", 11, FG_MED, True))
        ph.addStretch()
        self._total_prog = QProgressBar()
        self._total_prog.setRange(0, 100)
        self._total_prog.setValue(0)
        self._total_prog.setFixedWidth(200)
        self._total_prog.setFixedHeight(8)
        self._total_prog.setStyleSheet(f"""
            QProgressBar {{background:{SURFACE2}; border:none; border-radius:4px;}}
            QProgressBar::chunk {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {CYAN});
                border-radius:4px;
            }}
        """)
        ph.addWidget(self._total_prog)
        pgl.addLayout(ph)

        # Module progress bars
        self._prog_bars: Dict[str, ModuleProgress] = {}
        grid = QGridLayout()
        grid.setSpacing(4)
        for i, (key, icon, label, _) in enumerate(self.MODULES):
            mp = ModuleProgress(key, icon, label)
            self._prog_bars[key] = mp
            grid.addWidget(mp, i // 2, i % 2)
        pgl.addLayout(grid)
        lay.addWidget(prog_widget)

        # ── Tabs: Results / Dorks ──────────────────
        tabs_bar = QWidget()
        tabs_bar.setFixedHeight(38)
        tabs_bar.setStyleSheet(f"background:{BG}; border-bottom:1px solid {BORDER};")
        tb_lay = QHBoxLayout(tabs_bar)
        tb_lay.setContentsMargins(16, 0, 16, 0)
        tb_lay.setSpacing(0)

        self._tab_results = self._make_tab("📊  النتائج", True)
        self._tab_dorks   = self._make_tab("🎯  Dorks", False)
        self._tab_results.clicked.connect(lambda: self._switch_tab(0))
        self._tab_dorks.clicked.connect(lambda: self._switch_tab(1))
        tb_lay.addWidget(self._tab_results)
        tb_lay.addWidget(self._tab_dorks)
        tb_lay.addStretch()

        # Filter by severity
        sev_combo = QComboBox()
        sev_combo.addItems(["كل النتائج", "حرجة", "عالية", "متوسطة", "منخفضة", "معلومات"])
        sev_combo.setFixedHeight(26)
        sev_combo.setFixedWidth(110)
        sev_combo.setStyleSheet(f"""
            QComboBox {{
                background:{SURFACE}; color:{FG_MED}; border:1px solid {BORDER2};
                border-radius:4px; padding:0 8px; font-size:11px; font-family:{FONT_UI};
            }}
            QComboBox::drop-down {{ border:none; width:14px; }}
            QComboBox QAbstractItemView {{
                background:{SURFACE2}; color:{FG};
                border:1px solid {BORDER2};
                selection-background-color:{ACCENT_DIM};
            }}
        """)
        tb_lay.addWidget(sev_combo)
        tb_lay.addSpacing(8)

        # Export / Clear buttons
        export_btn = qbtn("📤", small=True)
        export_btn.setFixedWidth(32)
        export_btn.setToolTip("تصدير النتائج")
        export_btn.clicked.connect(self._export_findings)
        tb_lay.addWidget(export_btn)

        clear_btn = qbtn("🗑", small=True)
        clear_btn.setFixedWidth(32)
        clear_btn.setToolTip("مسح النتائج")
        clear_btn.clicked.connect(self._clear_findings)
        tb_lay.addWidget(clear_btn)

        # Counter
        self._counter_lbl = qlabel("0 نتيجة", 11, FG_DIM)
        self._counter_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._counter_lbl.setFixedWidth(70)
        tb_lay.addWidget(self._counter_lbl)

        lay.addWidget(tabs_bar)

        # ── Content stack ──────────────────────────
        self._content_stack = QStackedWidget()

        # Findings table
        self._findings_table = FindingsTable()
        self._content_stack.addWidget(self._findings_table)

        # Dorks panel
        self._dorks_panel = DorksPanel()
        self._content_stack.addWidget(self._dorks_panel)

        lay.addWidget(self._content_stack, stretch=1)
        return center

    def _build_status_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(24)
        bar.setStyleSheet(f"background:{BG}; border-top:1px solid {BORDER};")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(14, 0, 14, 0)
        lay.setSpacing(16)

        self._sb_target   = qlabel("—", 10, FG_DIM)
        self._sb_findings = qlabel("0 نتيجة", 10, FG_DIM)
        self._sb_time     = qlabel("", 10, FG_DIM)
        self._sb_db       = qlabel(f"DB: {self._db.db_path}", 10, FG_DIM)

        for w in [self._sb_target, self._sb_findings, self._sb_time]:
            lay.addWidget(w)
        lay.addStretch()
        lay.addWidget(self._sb_db)
        return bar

    def _make_tab(self, text: str, active: bool) -> QPushButton:
        btn = QPushButton(text)
        btn.setFixedHeight(38)
        btn.setMinimumWidth(120)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setCheckable(True)
        btn.setChecked(active)
        btn.setStyleSheet(f"""
            QPushButton {{
                background:transparent; color:{FG_MED}; border:none;
                border-bottom:2px solid transparent;
                font-size:12px; font-family:{FONT_UI}; padding:0 16px;
            }}
            QPushButton:checked {{
                color:{FG}; border-bottom-color:{ACCENT};
            }}
            QPushButton:hover:!checked {{ color:{FG}; }}
        """)
        return btn

    def _switch_tab(self, idx: int):
        self._content_stack.setCurrentIndex(idx)
        self._tab_results.setChecked(idx == 0)
        self._tab_dorks.setChecked(idx == 1)

    def _on_module_toggled(self, key: str, active: bool):
        pass

    # ─────────────────────────────────────────────
    # Scanning
    # ─────────────────────────────────────────────

    def _start_scan(self):
        target = self._target_input.text().strip()
        if not target:
            self._target_input.setFocus()
            return

        if self._running:
            return

        # Clean target
        if target.startswith("http://") or target.startswith("https://"):
            from urllib.parse import urlparse
            target = urlparse(target).netloc or target

        self._running = True
        self._finding_count = 0
        self._modules_done  = 0
        self._scan_start    = datetime.now()

        # UI state
        self._scan_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._findings_table.clear_findings()
        self._total_prog.setValue(0)
        self._counter_lbl.setText("0 نتيجة")
        self._title_bar.set_target(target)
        self._title_bar.set_status("جاري المسح...", YELLOW)
        self._sb_target.setText(f"الهدف: {target}")

        for mp in self._prog_bars.values():
            mp.reset()

        # Generate dorks
        self._dorks_panel.load_dorks(target)

        # New DB session
        active_modules = [k for k, btn in self._module_btns.items() if btn.is_active()]
        self._session_id  = self._db.new_session(target, active_modules)
        self._modules_total = len(active_modules)

        # Determine port range
        port_range_map = {0: "common", 1: "top1000", 2: "full"}
        port_range = port_range_map.get(self._port_combo.currentIndex(), "common")

        # Create and start scanners
        self._scanners = []

        scanner_map = {
            "DNS":   lambda: DNSScanner(target),
            "PORT":  lambda: PortScanner(target, {"port_range": port_range, "threads": 200}),
            "WHOIS": lambda: WHOISScanner(target),
            "SSL":   lambda: SSLScanner(target),
            "WEB":   lambda: WebScanner(target),
            "GEO":   lambda: GeoScanner(target),
            "SUB":   lambda: SubdomainScanner(target),
        }

        for key in active_modules:
            if key in scanner_map:
                scanner = scanner_map[key]()
                scanner.finding.connect(self._on_finding)
                scanner.progress.connect(lambda p, m, k=key: self._on_progress(k, p, m))
                scanner.finished_ok.connect(self._on_module_done)
                scanner.error.connect(self._on_module_error)
                self._module_btns[key].set_running(True)
                self._scanners.append((key, scanner))
                scanner.start()

    def _stop_scan(self):
        for key, scanner in self._scanners:
            scanner.stop()
        self._finish_scan()

    def _finish_scan(self):
        self._running = False
        self._scan_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._total_prog.setValue(100)

        elapsed = (datetime.now() - self._scan_start).seconds if hasattr(self, "_scan_start") else 0
        self._title_bar.set_status(
            f"مكتمل  ·  {self._finding_count} نتيجة  ·  {elapsed}ث", GREEN
        )
        self._sb_time.setText(f"المدة: {elapsed}ث")

        if self._session_id:
            self._db.end_session(self._session_id)
        self._history.refresh()

    def _on_finding(self, finding: Finding):
        self._findings_table.add_finding(finding)
        self._finding_count += 1
        self._counter_lbl.setText(f"{self._finding_count} نتيجة")
        self._sb_findings.setText(f"{self._finding_count} نتيجة")

        if self._session_id:
            self._db.save_finding(self._session_id, finding)

    def _on_progress(self, key: str, pct: int, msg: str):
        if key in self._prog_bars:
            self._prog_bars[key].update_progress(pct, msg)
        # Update total progress
        total = sum(
            self._prog_bars[k]._bar.value()
            for k in self._prog_bars
            if k in [m for m, _ in self._scanners]
        )
        n = max(1, len(self._scanners))
        self._total_prog.setValue(total // n)

    def _on_module_done(self, key: str):
        if key in self._prog_bars:
            self._prog_bars[key].set_done()
        if key in self._module_btns:
            self._module_btns[key].set_done()
        self._modules_done += 1
        if self._modules_done >= self._modules_total:
            self._finish_scan()

    def _on_module_error(self, key: str, error: str):
        if key in self._prog_bars:
            self._prog_bars[key].set_error(error)
        self._modules_done += 1
        if self._modules_done >= self._modules_total:
            self._finish_scan()

    def _load_session(self, session_id: int):
        """Load a past scan session into the table."""
        self._findings_table.clear_findings()
        findings = self._db.load_findings(session_id)
        for f in findings:
            self._findings_table.add_finding(f)
        self._finding_count = len(findings)
        self._counter_lbl.setText(f"{self._finding_count} نتيجة")

    def _export_findings(self):
        if self._finding_count == 0:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "تصدير النتائج", "phantom_recon_results.txt",
            "Text (*.txt);;JSON (*.json)"
        )
        if path:
            if path.endswith(".json") and self._session_id:
                content = self._db.export_json(self._session_id)
            else:
                content = self._findings_table.export_text()
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

    def _clear_findings(self):
        self._findings_table.clear_findings()
        self._finding_count = 0
        self._counter_lbl.setText("0 نتيجة")

    # ── Frameless resize ──────────────────────────

    MARGIN = 5
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            edge = self._edge(e.position().toPoint())
            if edge:
                self._re = edge
                self._rs = e.globalPosition().toPoint()
                self._rr = self.geometry()

    def mouseMoveEvent(self, e):
        if hasattr(self, "_re") and self._re:
            d = e.globalPosition().toPoint() - self._rs
            r = QRect(self._rr)
            if "e" in self._re: r.setRight(r.right()   + int(d.x()))
            if "s" in self._re: r.setBottom(r.bottom() + int(d.y()))
            if "w" in self._re: r.setLeft(r.left()     + int(d.x()))
            if "n" in self._re: r.setTop(r.top()       + int(d.y()))
            if r.width() >= self.minimumWidth() and r.height() >= self.minimumHeight():
                self.setGeometry(r)

    def mouseReleaseEvent(self, e): self._re = None

    def _edge(self, pos):
        m, w, h = self.MARGIN, self.width(), self.height()
        x, y = pos.x(), pos.y()
        if x<=m and y<=m:     return "nw"
        if x>=w-m and y<=m:   return "ne"
        if x<=m and y>=h-m:   return "sw"
        if x>=w-m and y>=h-m: return "se"
        if x<=m:               return "w"
        if x>=w-m:             return "e"
        if y<=m:               return "n"
        if y>=h-m:             return "s"
        return None

    def closeEvent(self, e):
        self._stop_scan()
        self._db.close()
        e.accept()
