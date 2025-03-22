import base64
from cryptography.hazmat.primitives import hashes

from repository.db.db import load_sessions


from cryptography.hazmat.primitives.asymmetric import ec


def validate_signature(signature, message, public_key):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception as e:
        print(f"Signature validation failed: {e}")
        return False


# not working properly
def check_session_is_valid(org, public_key):
    sessions = load_sessions()
    if not sessions or "sessions" not in sessions:
        return True

    for session in sessions["sessions"].values():
        if (
            session["org"] == org
            and session.get("client_public_key", None) == public_key
        ):
            return False
    return True
