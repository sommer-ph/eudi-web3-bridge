import hashlib
from py_ecc.bn128 import G1, multiply, add, curve_order, FQ
import hmac
import secrets
import json

# Kurvenparameter
group_order = curve_order  # Klarere Benennung (anstatt p)
G = G1  # Generatorpunkt
field_modulus = FQ.field_modulus

def modinv(a, modulus):
    """Sichere modulare Inverse mit explizitem Parameternamen"""
    return pow(a, -1, modulus)

def generate_k(priv_key, msg_hash):
    """RFC6979 mit Schutz gegen k=0"""
    v = b'\x01' * 32
    k = b'\x00' * 32
    priv_bytes = priv_key.to_bytes(32, 'big')
    msg_hash_bytes = msg_hash.to_bytes(32, 'big')

    # RFC6979 Implementierung
    k = hmac.new(k, v + b'\x00' + priv_bytes + msg_hash_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + priv_bytes + msg_hash_bytes, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    k_int = int.from_bytes(v, 'big') % group_order
    # Schutz gegen k=0
    return k_int if k_int != 0 else 1


def ecdsa_sign(priv_key, msg_hash):
    """Robustere Signaturerstellung mit Checks"""
    k = generate_k(priv_key, msg_hash)

    R = multiply(G, k)
    # Explizite Verwendung von FQ.n für Feld-Element
    r = R[0].n % group_order
    if r == 0:
        raise ValueError("r darf nicht 0 sein")

    s = (modinv(k, group_order) * (msg_hash + r * priv_key)) % group_order
    if s == 0:
        raise ValueError("s darf nicht 0 sein")

    return (r, s)


def ecdsa_verify(pub_key, msg_hash, sig):
    """Verifikation mit sauberer API (nur Boolean-Rückgabe)"""
    r, s = sig

    # Boundary Checks
    if r >= group_order or s >= group_order or r == 0 or s == 0:
        return False

    try:
        w = modinv(s, group_order)
        u1 = (msg_hash * w) % group_order
        u2 = (r * w) % group_order
        P = add(multiply(G, u1), multiply(pub_key, u2))
        return int(P[0].n) % group_order == r
    except:
        return False


# Beispiel mit sicherer Schlüsselgenerierung
priv_key = secrets.randbelow(group_order - 1) + 1  # Vermeidet 0
pub_key = multiply(G, priv_key)
msg = b"ECDSA over BN254 test message"
msg_hash = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % group_order

try:
    # Signatur erzeugen
    r, s = ecdsa_sign(priv_key, msg_hash)

    # Daten für JSON vorbereiten (mit w, q1, q2)
    w = modinv(s, group_order)

    # Berechnung von q1 und q2
    zw = msg_hash * w
    q1 = zw // group_order
    k1 = zw - q1 * group_order
    rw = r * w
    q2 = rw // group_order
    k2 = rw - q2 * group_order

    P1 = multiply(G, k1)
    P2 = multiply(pub_key, k2)
    R_circ = add(P1, P2)
    Rx_full = R_circ[0].n
    q3 = Rx_full // group_order
    rx_mod = Rx_full - q3 * group_order
    assert rx_mod % group_order == r, "Rx_full % n != r"

    output_data = {
        "z": str(msg_hash),
        "Qx": str(pub_key[0].n),  # Explizit FQ.n
        "Qy": str(pub_key[1].n),
        "r": str(r),
        "s": str(s),
        "w": str(w),
        "q1": str(q1),
        "q2": str(q2),
        "q3": str(q3)
    }

    # Ausgabe in Datei
    with open("ecdsa_output.json", "w") as f:
        json.dump(output_data, f, indent=4)

    # Verifikation
    valid = ecdsa_verify(pub_key, msg_hash, (r, s))
    print("Daten wurden gespeichert. Verifikation:", valid)

except ValueError as e:
    print(f"Fehler bei Signaturerstellung: {e}")