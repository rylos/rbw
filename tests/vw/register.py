"""Create a test account on a local Vaultwarden (no browser needed)."""
import base64, hashlib, hmac, json, os, sys, urllib.request
from cryptography.hazmat.primitives import hashes, padding as sympad, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

url, email, password = sys.argv[1], sys.argv[2], sys.argv[3]
ITER = 600000
b64 = lambda b: base64.b64encode(b).decode()

master = hashlib.pbkdf2_hmac("sha256", password.encode(), email.lower().encode(), ITER, 32)
mph = b64(hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1, 32))
exp = lambda info: HKDFExpand(hashes.SHA256(), 32, info.encode()).derive(master)
enc_key, mac_key = exp("enc"), exp("mac")

def enc(data, ek, mk):
    iv = os.urandom(16)
    p = sympad.PKCS7(128).padder(); data = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    mac = hmac.new(mk, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"

sym = os.urandom(64)
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
pk8 = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

def post(path, body, accept="application/json"):
    req = urllib.request.Request(url + path, json.dumps(body).encode(),
                                 {"Content-Type": "application/json", "Accept": accept})
    return urllib.request.urlopen(req).read().decode()

token = json.loads(post("/identity/accounts/register/send-verification-email", {"email": email, "name": "test"}))
post("/identity/accounts/register/finish", {
    "email": email, "emailVerificationToken": token,
    "kdf": 0, "kdfIterations": ITER,
    "masterPasswordHash": mph, "key": enc(sym, enc_key, mac_key),
    "keys": {"publicKey": b64(pub), "encryptedPrivateKey": enc(pk8, sym[:32], sym[32:])},
})
print("registered", email)
