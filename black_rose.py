import sys
import socket
import hashlib
import psutil
import requests
import re
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QFrame, QLineEdit, QPushButton, QComboBox, 
                             QFileDialog, QTabWidget, QTextEdit, QListWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Global Configuration
VT_API_KEY = "YOUR_API_KEY_HERE"
SUSPICIOUS_PATTERNS = [
    r"os\.system\(", r"subprocess\.", r"eval\(", r"exec\(", 
    r"base64\.b64decode", r"socket\.connect", r"requests\.get",
    r"getattr\(", r"__import__\(", r"shutil\."
]

# Language Dictionary
LANGS = {
    "English": {
        "title": "BlackRose Sentinel v3.0 | Real-Time Protection",
        "tab1": "Network Auditor",
        "tab2": "Malware Lab",
        "tab3": "System Guard",
        "scan_btn": "Run Network Scan",
        "file_btn": "Analyze File (Local + Cloud)",
        "proc_btn": "Monitor Live Processes",
        "dir": Qt.LayoutDirection.LeftToRight
    },
    "العربية": {
        "title": "بلاك روز سنتينل v3.0 | الحماية الفورية",
        "tab1": "مدقق الشبكة",
        "tab2": "مختبر البرمجيات",
        "tab3": "حارس النظام",
        "scan_btn": "بدء فحص الشبكة",
        "file_btn": "تحليل ملف (محلي + سحابي)",
        "proc_btn": "مراقبة العمليات الحية",
        "dir": Qt.LayoutDirection.RightToLeft
    }
}

# 1. Real Network Scanning Logic
class ScanThread(QThread):
    result_ready = pyqtSignal(int, str)
    def __init__(self, target):
        super().__init__()
        self.target = target
    def run(self):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 8080]
        try:
            ip = socket.gethostbyname(self.target)
            for p in common_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                r = s.connect_ex((ip, p))
                self.result_ready.emit(p, "OPEN ✅" if r == 0 else "CLOSED ❌")
                s.close()
        except: pass

# 2. Heuristic + Cloud File Analysis Logic
class FileThread(QThread):
    analysis_ready = pyqtSignal(str)
    def __init__(self, path):
        super().__init__()
        self.path = path
    def run(self):
        report = "--- LOCAL HEURISTIC ANALYSIS ---\n"
        risk_score = 0
        
        # Local Static Analysis
        try:
            with open(self.path, "r", errors="ignore") as f:
                content = f.read()
                for pattern in SUSPICIOUS_PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        risk_score += 15 * len(matches)
                        report += f"[!] Found Suspicious Pattern: {pattern}\n"
            
            if risk_score > 60: report += "RESULT: CRITICAL RISK ⚠️\n"
            elif risk_score > 0: report += "RESULT: SUSPICIOUS 🔍\n"
            else: report += "RESULT: CLEAN (Local) ✅\n"
        except: report += "Error reading file for local scan.\n"

        # Cloud Analysis (VirusTotal)
        report += "\n--- CLOUD INTELLIGENCE (VirusTotal) ---\n"
        sha256 = hashlib.sha256()
        with open(self.path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)
        f_hash = sha256.hexdigest()
        
        url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            res = requests.get(url, headers=headers)
            if res.status_code == 200:
                stats = res.json()['data']['attributes']['last_analysis_stats']
                report += f"Malicious Flags: {stats['malicious']}\n"
                report += f"Undetected by: {stats['harmless']} engines\n"
            else: report += "Hash not found in global database.\n"
        except: report += "Cloud Connection Failed.\n"
        
        self.analysis_ready.emit(report)

# 3. Live System Process Logic
class ProcessThread(QThread):
    proc_signal = pyqtSignal(str)
    def run(self):
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                self.proc_signal.emit(f"PID: {proc.info['pid']} | Name: {proc.info['name']} | User: {proc.info['username']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue

# Main Application UI
class BlackRoseSentinel(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(650, 600)
        self.setStyleSheet("background-color: #0d1117; color: #c9d1d9; font-family: 'Consolas', 'Segoe UI';")
        self.layout = QVBoxLayout()
        
        self.lang_sel = QComboBox()
        self.lang_sel.addItems(["English", "العربية"])
        self.lang_sel.currentTextChanged.connect(self.update_lang)
        self.layout.addWidget(self.lang_sel)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("QTabBar::tab { background: #161b22; padding: 12px; min-width: 100px; } QTabBar::tab:selected { border-bottom: 2px solid #58a6ff; color: #58a6ff; }")
        
        # Network Tab
        self.net_tab = QWidget()
        net_l = QVBoxLayout(self.net_tab)
        self.ip_input = QLineEdit()
        self.ip_input.setStyleSheet("background: #010409; border: 1px solid #30363d; padding: 8px;")
        self.net_btn = QPushButton()
        self.net_btn.setStyleSheet("background: #238636; font-weight: bold; padding: 10px;")
        self.net_list = QListWidget()
        net_l.addWidget(self.ip_input)
        net_l.addWidget(self.net_btn)
        net_l.addWidget(self.net_list)
        self.net_btn.clicked.connect(self.run_net_scan)

        # Malware Lab Tab
        self.file_tab = QWidget()
        file_l = QVBoxLayout(self.file_tab)
        self.f_btn = QPushButton()
        self.f_btn.setStyleSheet("background: #8957e5; font-weight: bold; padding: 10px;")
        self.f_res = QTextEdit()
        self.f_res.setStyleSheet("background: #010409; color: #7ee787;")
        file_l.addWidget(self.f_btn)
        file_l.addWidget(self.f_res)
        self.f_btn.clicked.connect(self.run_file_scan)

        # System Guard Tab
        self.proc_tab = QWidget()
        proc_l = QVBoxLayout(self.proc_tab)
        self.proc_list = QListWidget()
        self.proc_btn = QPushButton()
        self.proc_btn.setStyleSheet("background: #21262d; border: 1px solid #30363d; padding: 10px;")
        proc_l.addWidget(self.proc_list)
        proc_l.addWidget(self.proc_btn)
        self.proc_btn.clicked.connect(self.run_proc_scan)

        self.tabs.addTab(self.net_tab, "")
        self.tabs.addTab(self.file_tab, "")
        self.tabs.addTab(self.proc_tab, "")
        
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)
        self.update_lang("English")

    def update_lang(self, lang):
        d = LANGS[lang]
        self.setWindowTitle(d["title"])
        self.tabs.setTabText(0, d["tab1"])
        self.tabs.setTabText(1, d["tab2"])
        self.tabs.setTabText(2, d["tab3"])
        self.net_btn.setText(d["scan_btn"])
        self.f_btn.setText(d["file_btn"])
        self.proc_btn.setText(d["proc_btn"])
        self.ip_input.setPlaceholderText("Target Domain/IP (e.g. google.com)")
        self.setLayoutDirection(d["dir"])

    def run_net_scan(self):
        self.net_list.clear()
        self.nt = ScanThread(self.ip_input.text())
        self.nt.result_ready.connect(lambda p, s: self.net_list.addItem(f"PORT {p}: {s}"))
        self.nt.start()

    def run_file_scan(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.f_res.setText("Initializing Deep Scan...")
            self.ft = FileThread(path)
            self.ft.analysis_ready.connect(self.f_res.setText)
            self.ft.start()

    def run_proc_scan(self):
        self.proc_list.clear()
        self.pt = ProcessThread()
        self.pt.proc_signal.connect(self.proc_list.addItem)
        self.pt.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BlackRoseSentinel()
    window.show()
    sys.exit(app.exec())