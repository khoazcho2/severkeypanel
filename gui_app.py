import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import requests
from datetime import datetime

# SERVER API
SERVER_URL = "https://web-production-638c33.up.railway.app"


class QuocServer(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("HoQuoc Server Panel")
        self.setFixedSize(1000, 600)

        self.token = None

        self.initUI()
        self.show_login()

    def initUI(self):

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout()
        central.setLayout(layout)

        top = QHBoxLayout()

        top.addWidget(QLabel("Max Devices"))

        self.max_devices = QSpinBox()
        self.max_devices.setValue(1)
        self.max_devices.setMaximum(999)

        top.addWidget(self.max_devices)

        top.addSpacing(20)

        top.addWidget(QLabel("Days (0 = Unlimited)"))

        self.days = QSpinBox()
        self.days.setValue(0)
        self.days.setMaximum(999)

        top.addWidget(self.days)

        top.addSpacing(20)

        self.generate_btn = QPushButton("Generate Key")
        self.generate_btn.clicked.connect(self.generate_key)
        top.addWidget(self.generate_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_keys)
        top.addWidget(self.refresh_btn)

        top.addStretch()

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.clicked.connect(self.logout)
        top.addWidget(self.logout_btn)

        layout.addLayout(top)

        # TABLE

        self.table = QTableWidget()
        self.table.setColumnCount(10)

        self.table.setHorizontalHeaderLabels([
            "ID",
            "Key",
            "MaxDev",
            "Used",
            "Days",
            "Status",
            "Created",
            "FirstUsed",
            "Expire",
            "HWID"
        ])

        self.table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.table)

        # AUTO REFRESH

        self.timer = QTimer()
        self.timer.timeout.connect(self.load_keys)
        self.timer.start(5000)

    # LOGIN WINDOW

    def show_login(self):

        dialog = QDialog(self)
        dialog.setWindowTitle("Admin Login")
        dialog.setFixedSize(300, 180)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Username"))

        self.username = QLineEdit()
        layout.addWidget(self.username)

        layout.addWidget(QLabel("Password"))

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password)

        login = QPushButton("Login")
        login.clicked.connect(lambda: self.login(dialog))

        layout.addWidget(login)

        dialog.setLayout(layout)

        dialog.exec_()

    # LOGIN REQUEST

    def login(self, dialog):

        user = self.username.text()
        pwd = self.password.text()

        try:

            r = requests.post(
                f"{SERVER_URL}/login",
                json={
                    "username": user,
                    "password": pwd
                }
            )

            if r.status_code == 200:

                self.token = r.json()["token"]

                dialog.accept()

                self.load_keys()

            else:

                QMessageBox.warning(self, "Error", "Login failed")

        except Exception as e:

            QMessageBox.critical(self, "Error", str(e))

    # LOAD KEYS

    def load_keys(self):

        if not self.token:
            return

        try:

            r = requests.get(
                f"{SERVER_URL}/keys",
                headers={"Authorization": f"Bearer {self.token}"}
            )

            if r.status_code != 200:
                return

            keys = r.json()["keys"]

            self.table.setRowCount(len(keys))

            for row, key in enumerate(keys):

                self.table.setItem(row, 0, QTableWidgetItem(str(key["id"])))
                self.table.setItem(row, 1, QTableWidgetItem(key["key"]))
                self.table.setItem(row, 2, QTableWidgetItem(str(key["max_devices"])))
                self.table.setItem(row, 3, QTableWidgetItem(str(key["used"])))

                days = key["duration_days"]
                self.table.setItem(row, 4, QTableWidgetItem("∞" if days == 0 else str(days)))

                self.table.setItem(row, 5, QTableWidgetItem(key["status"]))

                self.table.setItem(row, 6, QTableWidgetItem(str(key["created_by"])))

                first = key.get("first_used")
                self.table.setItem(row, 7, QTableWidgetItem(str(first) if first else "-"))

                expire = key.get("expire_at")
                self.table.setItem(row, 8, QTableWidgetItem(self.countdown(expire)))

                hwid = key.get("hwid")
                self.table.setItem(row, 9, QTableWidgetItem(hwid if hwid else "-"))

        except Exception as e:
            print(e)

    # COUNTDOWN

    def countdown(self, expire):

        if not expire:
            return "∞"

        try:

            expire = expire.replace("Z", "+00:00")
            exp = datetime.fromisoformat(expire)

            now = datetime.utcnow()

            diff = exp - now

            if diff.total_seconds() <= 0:
                return "Expired"

            d = diff.days
            h = diff.seconds // 3600

            return f"{d}d {h}h"

        except:
            return "-"

    # GENERATE KEY

    def generate_key(self):

        if not self.token:
            return

        try:

            r = requests.post(
                f"{SERVER_URL}/generate_key",
                json={
                    "duration_days": self.days.value(),
                    "max_devices": self.max_devices.value()
                },
                headers={"Authorization": f"Bearer {self.token}"}
            )

            if r.status_code == 200:

                key = r.json()["key"]

                QMessageBox.information(self, "Success", f"Key: {key}")

                self.load_keys()

        except Exception as e:

            QMessageBox.critical(self, "Error", str(e))

    # LOGOUT

    def logout(self):

        self.token = None

        self.show_login()


if __name__ == "__main__":

    app = QApplication(sys.argv)

    win = QuocServer()
    win.show()

    sys.exit(app.exec_())
