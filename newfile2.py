from PyQt6.QtWidgets import ( QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QLabel, QTextEdit, QSplitter, QLineEdit, QPushButton, QTabWidget, QMessageBox, QFileDialog, QListWidget, QHBoxLayout ) 
from PyQt6.QtCore import Qt, QTimer, QDateTime, QThread, pyqtSignal 
import sys 
import json 
import requests 
import traceback 
import logging 
from fpdf import FPDF 
from core.auth_analyzer import AuthAnalyzer from core.bruteforcer import BruteForcer from core.websocket_listener import WebSocketListener


logging.basicConfig( level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[ logging.FileHandler("vulcanstrike.log"), logging.StreamHandler(sys.stdout) ] )

def start_gui(proxy_instance, scanner_instance, auth_analyzer_instance, ai_suggester_instance): app = QApplication(sys.argv) window = ProxyGUI(proxy_instance, scanner_instance, auth_analyzer_instance, ai_suggester_instance) window.show() sys.exit(app.exec())

class ScannerThread(QThread): result_signal = pyqtSignal(list) error_signal = pyqtSignal(str)

def __init__(self, scanner, url):
    super().__init__()
    self.scanner = scanner
    self.url = url

def run(self):
    try:
        results = self.scanner.scan(self.url)
        self.result_signal.emit(results)
    except Exception as e:
        self.error_signal.emit(str(e))

class WorkerThread(QThread): result_signal = pyqtSignal(object) error_signal = pyqtSignal(str)

def __init__(self, func, *args):
    super().__init__()
    self.func = func
    self.args = args

def run(self):
    try:
        result = self.func(*self.args)
        self.result_signal.emit(result)
    except Exception as e:
        self.error_signal.emit(str(e))

class ProxyGUI(QWidget): def init(self, proxy_instance, scanner_instance, auth_analyzer_instance, ai_suggester_instance): super().init() self.setWindowTitle("Gengar VulcanStrike - Web Security Toolkit") self.resize(1280, 750)

self.proxy = proxy_instance
    self.scanner = scanner_instance
    self.auth_analyzer = auth_analyzer_instance
    self.ai_suggester = ai_suggester_instance
    self.ws_listener = None

    self.tabs = QTabWidget(self)
    self.proxy_tab = QWidget()
    self.scan_tab = QWidget()
    self.token_tab = QWidget()
    self.ai_tab = QWidget()
    self.brute_tab = QWidget()
    self.websocket_tab = QWidget()
    self.log_tab = QWidget()

    self.tabs.addTab(self.proxy_tab, "Proxy")
    self.tabs.addTab(self.scan_tab, "Scanner")
    self.tabs.addTab(self.token_tab, "Token Analyzer")
    self.tabs.addTab(self.ai_tab, "Payload Suggester")
    self.tabs.addTab(self.brute_tab, "BruteForcer")
    self.tabs.addTab(self.websocket_tab, "WebSocket Listener")
    self.tabs.addTab(self.log_tab, "Logs & Simulation")

    self.init_proxy_tab()
    self.init_scan_tab()
    self.init_token_tab()
    self.init_ai_tab()
    self.init_brute_tab()
    self.init_websocket_tab()
    self.init_log_tab()

    main_layout = QVBoxLayout(self)
    main_layout.addWidget(self.tabs)

def log_event(self, message, level="info"):
    timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
    self.log_output.append(f"[{timestamp}] {message}")

    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)

def init_log_tab(self):
    layout = QVBoxLayout()
    self.log_output = QTextEdit()
    self.log_output.setReadOnly(True)

    self.simulate_button = QPushButton("Run Test Simulation")
    self.simulate_button.clicked.connect(self.run_test_scenario)

    layout.addWidget(QLabel("System Log:"))
    layout.addWidget(self.log_output)
    layout.addWidget(self.simulate_button)

    self.log_tab.setLayout(layout)

def run_test_scenario(self):
    self.log_event("[TEST] Starting simulation scenario...")
    try:
        test_url = "http://testsite.com/page.php?id=FUZZ"
        results = self.scanner.scan(test_url)
        self.log_event(f"[Scanner] Tested {test_url} — Found {len(results)} results.")

        brute = BruteForcer("http://testsite.com/login")
        result = brute.run(["admin"], ["1234"])
        self.log_event(f"[BruteForce] Login result: {result if result else 'No match'}")

        self.log_event("[WebSocket] Simulated socket message: Hello from test!")
        self.log_event("[TEST] Simulation completed.")
    except Exception as e:
        tb = traceback.format_exc()
        self.log_event(f"[ERROR] Test scenario failed: {e}", level="error")
        logging.error(tb)
        QMessageBox.critical(self, "Simulation Error", str(e))

def perform_scan(self):
    url = self.scan_input.text()
    if not url or "FUZZ" not in url:
        QMessageBox.warning(self, "Invalid Input", "Please enter a URL containing 'FUZZ'.")
        return

    self.log_event(f"Starting scan on {url}")
    self.scan_results.clear()

    self.scan_thread = ScannerThread(self.scanner, url)
    self.scan_thread.result_signal.connect(self.display_scan_results)
    self.scan_thread.error_signal.connect(self.handle_scan_error)
    self.scan_thread.start()

def display_scan_results(self, results):
    for res in results:
        self.scan_results.addItem(res)
    self.log_event(f"Scan completed. {len(results)} results found.")

def handle_scan_error(self, error_msg):
    self.log_event(f"[ERROR] Scan failed: {error_msg}", level="error")
    QMessageBox.critical(self, "Scan Error", error_msg)

def analyze_token(self):
    token = self.token_input.toPlainText().strip()
    if not token:
        QMessageBox.warning(self, "Input Required", "Please enter a token to analyze.")
        return

    self.log_event("Token analysis started.")
    self.token_thread = WorkerThread(self.auth_analyzer.analyze, token)
    self.token_thread.result_signal.connect(self.display_token_result)
    self.token_thread.error_signal.connect(self.handle_token_error)
    self.token_thread.start()

def display_token_result(self, result):
    self.token_results.setPlainText(json.dumps(result, indent=4))
    self.log_event("Token analysis completed.")

def handle_token_error(self, error_msg):
    self.log_event(f"[ERROR] Token analysis failed: {error_msg}", level="error")
    QMessageBox.critical(self, "Token Analysis Error", error_msg)

def get_ai_payload(self):
    context = self.ai_input.text().strip()
    if not context:
        QMessageBox.warning(self, "Context Required", "Please describe the context.")
        return

    self.log_event("AI Payload Suggestion requested.")
    self.ai_thread = WorkerThread(self.ai_suggester.suggest, context)
    self.ai_thread.result_signal.connect(self.display_ai_suggestions)
    self.ai_thread.error_signal.connect(self.handle_ai_error)
    self.ai_thread.start()

def display_ai_suggestions(self, suggestions):
    self.ai_results.setPlainText("\n".join(suggestions))
    self.log_event("AI suggestions generated.")

def handle_ai_error(self, error_msg):
    self.log_event(f"[ERROR] AI suggestion failed: {error_msg}", level="error")
    QMessageBox.critical(self, "AI Suggestion Error", error_msg)

def start_brute_force(self):
    url = self.brute_url.text().strip()
    users = self.user_list.toPlainText().splitlines()
    passwords = self.pass_list.toPlainText().splitlines()

    if not url or not users or not passwords:
        QMessageBox.warning(self, "Input Missing", "URL, usernames, and passwords are required.")
        return

    self.log_event(f"Brute-force started on {url}")
    self.brute_thread = WorkerThread(BruteForcer(url).run, users, passwords)
    self.brute_thread.result_signal.connect(self.display_brute_result)
    self.brute_thread.error_signal.connect(self.handle_brute_error)
    self.brute_thread.start()

def display_brute_result(self, result):
    if result:
        self.brute_results.setPlainText(f"Valid credentials found: {result}")
        self.log_event(f"[BruteForce] Success: {result}")
    else:
        self.brute_results.setPlainText("No valid credentials found.")
        self.log_event("[BruteForce] No valid credentials.")

def handle_brute_error(self, error_msg):
    self.log_event(f"[ERROR] BruteForce failed: {error_msg}", level="error")
    QMessageBox.critical(self, "BruteForce Error", error_msg)

def start_websocket(self):
    url = self.ws_url.text().strip()
    if not url:
        QMessageBox.warning(self, "URL Required", "Please enter a WebSocket URL.")
        return

    try:
        self.ws_listener = WebSocketListener(url, self.log_websocket_message)
        self.ws_listener.start()
        self.log_event(f"WebSocket connected to {url}")
    except Exception as e:
        tb = traceback.format_exc()
        self.log_event(f"[ERROR] WebSocket failed: {e}", level="error")
        logging.error(tb)
        QMessageBox.critical(self, "WebSocket Error", str(e))

def log_websocket_message(self, msg):
    self.ws_log.append(msg)
    self.log_event(f"[WebSocket] {msg}")