"""Independent Bitwarden client for checking rbw's writes against a local Vaultwarden.

  bwtool.py URL EMAIL PASSWORD dump              decrypt the whole vault (incl. attachments' sha256)
  bwtool.py URL EMAIL PASSWORD mkkeyed NAME      create a login that has its own item key
  bwtool.py URL EMAIL PASSWORD apikey            print the personal api key (client_id client_secret)
  bwtool.py URL EMAIL PASSWORD mkorg NAME COLL...  create an organization with these collections
"""
import base64, hashlib, hmac, json, os, sys, urllib.parse, urllib.request, uuid
from cryptography.hazmat.primitives import hashes, padding as sympad, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

url, email, password, cmd = sys.argv[1:5]
b64, unb64 = (lambda b: base64.b64encode(b).decode()), base64.b64decode

def req(method, path, body=None, token=None, form=False, raw=False):
    # vaultwarden only sends ssh keys to clients from 2024.12 on
    headers = {"Accept": "application/json", "Device-Type": "8", "Bitwarden-Client-Version": "2024.12.0"}
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.urlopen(urllib.request.Request(url + path, data, headers, method=method))
    out = r.read()
    return out if raw else (json.loads(out) if out else None)

pre = req("POST", "/identity/accounts/prelogin", {"email": email})
master = hashlib.pbkdf2_hmac("sha256", password.encode(), email.lower().encode(), pre["kdfIterations"], 32)
mph = b64(hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1, 32))
tok = req("POST", "/identity/connect/token", {
    "grant_type": "password", "username": email, "password": mph, "scope": "api offline_access",
    "client_id": "web", "deviceType": "9", "deviceIdentifier": str(uuid.uuid5(uuid.NAMESPACE_DNS, email)),
    "deviceName": "bwtool"}, form=True)
at = tok["access_token"]
stretched = (HKDFExpand(hashes.SHA256(), 32, b"enc").derive(master), HKDFExpand(hashes.SHA256(), 32, b"mac").derive(master))

def dec_raw(cs, key):
    ty, rest = cs.split(".", 1); assert ty == "2", ty
    iv, ct, mac = [unb64(x) for x in rest.split("|")]
    assert hmac.compare_digest(hmac.new(key[1], iv + ct, hashlib.sha256).digest(), mac), "bad mac"
    d = Cipher(algorithms.AES(key[0]), modes.CBC(iv)).decryptor(); p = d.update(ct) + d.finalize()
    u = sympad.PKCS7(128).unpadder(); return u.update(p) + u.finalize()

def enc_raw(data, key):
    iv = os.urandom(16); p = sympad.PKCS7(128).padder(); data = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(key[0]), modes.CBC(iv)).encryptor(); ct = e.update(data) + e.finalize()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(hmac.new(key[1], iv + ct, hashlib.sha256).digest())}"

split = lambda k: (k[:32], k[32:])
sync = req("GET", "/api/sync", token=at)
ukey = split(dec_raw(sync["profile"]["key"], stretched))
privkey = serialization.load_der_private_key(dec_raw(sync["profile"]["privateKey"], ukey), None)
oaep = asympad.OAEP(asympad.MGF1(hashes.SHA1()), hashes.SHA1(), None)
def org_key(org_id):
    o = next(o for o in sync["profile"]["organizations"] if o["id"] == org_id)
    ty, ct = o["key"].split(".", 1); assert ty == "4", ty
    return split(privkey.decrypt(unb64(ct), oaep))
org_names = {o["id"]: o["name"] for o in sync["profile"]["organizations"]}
coll_names = {c["id"]: dec_raw(c["name"], org_key(c["organizationId"])).decode() for c in sync.get("collections") or []}

if cmd == "apikey":
    r = req("POST", "/api/accounts/api-key", {"masterPasswordHash": mph}, token=at)
    print("user." + sync["profile"]["id"], r["apiKey"])
elif cmd == "mkkeyed":
    ikey = os.urandom(64); k = split(ikey)
    e = lambda s: enc_raw(s.encode(), k)
    req("POST", "/api/ciphers", {
        "type": 1, "name": e(sys.argv[5]), "notes": e("nota keyed"), "key": enc_raw(ikey, ukey),
        "encryptedFor": sync["profile"]["id"], "favorite": True, "reprompt": 0,
        "login": {"username": e("ku"), "password": e("kp"), "totp": None,
                  "uris": [{"uri": e("https://keyed.example"), "match": None}],
                  "fido2Credentials": [{"credentialId": e("cred"), "keyType": e("public-key"), "keyAlgorithm": e("ECDSA"),
                      "keyCurve": e("P-256"), "keyValue": e("k"), "rpId": e("keyed.example"), "userHandle": e("h"),
                      "counter": e("0"), "rpName": e("x"), "userDisplayName": e("x"), "discoverable": e("true"),
                      "creationDate": "2026-10-22T00:00:00.000Z"}]},
        "fields": [{"type": 1, "name": e("hk"), "value": e("hv"), "linkedId": None}]}, token=at)
    print("created")
elif cmd == "mkorg":
    okey = os.urandom(64); k = split(okey)
    opriv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = opriv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv = opriv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    org = req("POST", "/api/organizations", {
        "name": sys.argv[5], "billingEmail": email, "planType": 0,
        "collectionName": enc_raw(sys.argv[6].encode(), k),
        "key": "4." + b64(privkey.public_key().encrypt(okey, oaep)),
        "keys": {"publicKey": b64(pub), "encryptedPrivateKey": enc_raw(priv, k)}}, token=at)
    for name in sys.argv[7:]:
        req("POST", f"/api/organizations/{org['id']}/collections", {
            "name": enc_raw(name.encode(), k), "groups": [], "users": []}, token=at)
    print(org["id"])
elif cmd == "dump":
    out = []
    for c in sync["ciphers"]:
        base = org_key(c["organizationId"]) if c.get("organizationId") else ukey
        k = split(dec_raw(c["key"], base)) if c.get("key") else base
        d = lambda v: dec_raw(v, k).decode() if v else None
        item = {"name": d(c["name"]), "type": c["type"], "keyed": bool(c.get("key")), "favorite": c.get("favorite"),
                "deleted": bool(c.get("deletedDate")), "notes": d(c.get("notes")),
                "fields": [[f["type"], d(f["name"]), d(f["value"])] for f in c.get("fields") or []],
                "history": [d(h["password"]) for h in c.get("passwordHistory") or []],
                "archived": bool(c.get("archivedDate")), "org": org_names.get(c.get("organizationId")),
                "collections": sorted(coll_names.get(i, i) for i in c.get("collectionIds") or [])}
        for section in ("card", "identity", "sshKey"):
            if c.get(section):
                item[section] = {key: d(v) for key, v in c[section].items() if isinstance(v, str)}
        if c.get("login"):
            l = c["login"]
            item["login"] = {"username": d(l.get("username")), "password": d(l.get("password")), "totp": d(l.get("totp")),
                             "uris": [d(u["uri"]) for u in l.get("uris") or []],
                             "uri_checksums_ok": all(d(u["uriChecksum"]) == b64(hashlib.sha256(d(u["uri"]).encode()).digest())
                                                     for u in l.get("uris") or [] if u.get("uriChecksum")),
                             "passkeys": len(l.get("fido2Credentials") or [])}
        atts = []
        for a in c.get("attachments") or []:
            ak = split(dec_raw(a["key"], k)) if a.get("key") else k
            meta = req("GET", f"/api/ciphers/{c['id']}/attachment/{a['id']}", token=at)
            u = meta["url"] if meta["url"].startswith("http") else url + meta["url"]
            blob = urllib.request.urlopen(u).read()
            assert blob[0] == 2
            iv, mac, ct = blob[1:17], blob[17:49], blob[49:]
            assert hmac.compare_digest(hmac.new(ak[1], iv + ct, hashlib.sha256).digest(), mac), "bad attachment mac"
            dd = Cipher(algorithms.AES(ak[0]), modes.CBC(iv)).decryptor(); p = dd.update(ct) + dd.finalize()
            un = sympad.PKCS7(128).unpadder(); p = un.update(p) + un.finalize()
            atts.append([d(a["fileName"]), hashlib.sha256(p).hexdigest()])
        item["attachments"] = atts
        out.append(item)
    print(json.dumps(sorted(out, key=lambda i: i["name"]), indent=1, ensure_ascii=False))
