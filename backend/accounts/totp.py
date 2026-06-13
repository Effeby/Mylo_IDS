import pyotp
import qrcode
import base64
import io


def generate_totp_secret():
    """Génère une clé secrète TOTP unique."""
    return pyotp.random_base32()


def get_totp_uri(secret, username, issuer="Mylo IPS"):
    """Génère l'URI pour le QR code Google Authenticator."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret, code):
    """Vérifie le code TOTP saisi par l'utilisateur (fenêtre ±1 intervalle)."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_qr_base64(uri):
    """Génère le QR code en base64 pour l'afficher dans l'app."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()