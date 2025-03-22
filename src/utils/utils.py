import time
import json
import base64
import os
import requests
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,
    ParameterFormat,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        data = json.load(key_file)
        private_key = data["private_key"]
        private_key_pem = base64.b64decode(private_key.encode("utf-8"))
        private_key = load_pem_private_key(
            private_key_pem,
            password=None,  # No password required for unencrypted keys
            backend=default_backend(),
        )

    return private_key


def load_salt(file_path):
    with open(file_path, "rb") as key_file:
        data = json.load(key_file)
        salt = data["salt"]
        return salt


def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        data = json.load(key_file)
        public_key = data["public_key"]
        return public_key


def create_authed_message(private_key, message):
    signature = sign_message(private_key, message.encode("utf-8"))
    return {
        "message": message,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }


def sign_message(private_key, message: bytes):
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def generate_key_pair():
    """Generate private and public keys for ECC"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize public key for transmission"""
    print("SERIALIZING PK")
    if isinstance(public_key, str):
        print("PK is str")
        public_key = base64.b64decode(public_key)

    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key(private_key):
    """Serialize private key for transmission"""
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def derive_shared_key(private_key, peer_public_key):
    """Derive the shared key using ECC private and public keys"""
    peer_public_key = deserialize_public_key(peer_public_key)

    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)

    return derived_key


def encrypt_message(message, shared_key, private_key=None):
    message_json = json.dumps(message).encode("utf-8")

    shared_key = shared_key.encode("utf-8")

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        backend=default_backend(),
        info=b"handshake data",
    ).derive(shared_key)

    iv = os.urandom(16)

    cipher = Cipher(
        algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(message_json) + encryptor.finalize()

    signature = None
    if private_key and private_key != "":
        if message_json is None or message_json == "":
            message_json = b""

        if isinstance(private_key, str):
            private_key = base64.b64decode(private_key)

        private_key = load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend(),
        )

        if not isinstance(message_json, bytes):
            message_json = message_json.encode("utf-8")
        signature = sign_message(private_key, message_json)

    certificate = {
        "encryption_method": "AES-256-GCM",
        "key_derivation": "HKDF-SHA256",
        "timestamp": time.time(),
        "message_integrity_tag": base64.b64encode(encryptor.tag).decode("utf-8"),
    }

    if signature:
        certificate["signature"] = base64.b64encode(signature).decode("utf-8")

    encrypted_payload = {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "certificate": certificate,
    }

    return encrypted_payload


def decrypt_message(encrypted_payload, shared_key, public_key=None):
    shared_key = shared_key.encode("utf-8")
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        backend=default_backend(),
        info=b"handshake data",
    ).derive(shared_key)

    iv = base64.b64decode(encrypted_payload["iv"])
    ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
    tag = base64.b64decode(encrypted_payload["certificate"]["message_integrity_tag"])
    signature = None
    if "signature" in encrypted_payload["certificate"] and public_key:
        signature = base64.b64decode(encrypted_payload["certificate"]["signature"])

    cipher = Cipher(
        algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend()
    )
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)

    if public_key:
        if isinstance(public_key, str):
            public_key = public_key.encode("utf-8")
            print("Public key is str")
            public_key = base64.b64decode(public_key)
            public_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend(),
            )

        public_key.verify(
            signature,
            decrypted_message,
            ec.ECDSA(hashes.SHA256()),
        )

    return json.loads(decrypted_message.decode("utf-8"))


def deserialize_public_key(serialized_key):
    """Deserialize public key from transmission"""
    return serialization.load_pem_public_key(
        serialized_key,
        backend=default_backend(),
    )


def serialize_dh_parameters(parameters):
    """Correctly serialize Diffie-Hellman parameters"""
    return parameters.parameter_bytes(
        encoding=Encoding.PEM, format=ParameterFormat.PKCS3
    )


def deserialize_dh_parameters(serialized_parameters):
    """Correctly deserialize Diffie-Hellman parameters"""
    return serialization.load_pem_parameters(
        serialized_parameters,
        backend=default_backend(),
    )


def send_encrypted_message(payload, session_id, shared_key, url, type="POST"):
    encrypted_payload = encrypt_message(payload, shared_key, None)

    payload = {
        "session_id": session_id,
        "payload": encrypted_payload,
    }

    if type == "POST":
        response = requests.post(url, json=payload)
    elif type == "GET":
        response = requests.get(url, json=payload)

    return response


def send_authed_message(payload, session, url, type="POST"):
    shared_key = session["shared_key"]
    session_id = session["session_id"]
    private_key = session["private_key"]

    if not private_key:
        private_key = None

    encrypted_payload = encrypt_message(payload, shared_key, private_key)

    payload = {
        "session_id": session_id,
        "payload": encrypted_payload,
    }

    if type == "POST":
        response = requests.post(url, json=payload)
    elif type == "GET":
        response = requests.get(url, json=payload)
    elif type == "PUT":
        response = requests.put(url, json=payload)
    elif type == "DELETE":
        response = requests.delete(url, json=payload)

    return response


def receive_encrypted_message(payload, sessions):
    session_id = payload["session_id"]
    encrypted_payload = payload["payload"]

    session = sessions["sessions"][session_id]
    life_span = session["life_span"]

    if life_span < time.time():
        return {"error": "Session has expired"}

    if not session:
        return {"error": "Session not found."}

    shared_key = session["shared_key"]

    public_key = session["client_public_key"]

    decrypted_payload = decrypt_message(encrypted_payload, shared_key, public_key)

    return decrypted_payload
