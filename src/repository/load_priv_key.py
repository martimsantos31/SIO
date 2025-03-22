import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_private_key():
    """
    Load a private key from a file

    Args:
        private_key_path(str): Path to the private key file

    Returns:
        private_key: The deserialized RSA private key object
    """
    dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
    load_dotenv(dotenv_path)

    private_key_path = os.getenv("REP_PRIV_KEY_PATH")
    if not private_key_path:
        raise ValueError("REP_PRIV_KEY_PATH not found in .env")

    private_key_path = os.path.join(
        os.path.dirname(__file__), private_key_path)

    with open(private_key_path, "rb") as f:
        private_key_bytes = f.read()

        print("hi")
        print(private_key_bytes)
    return serialization.load_pem_private_key(
        private_key_bytes, password=None, backend=default_backend()
    )
