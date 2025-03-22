import time
import uuid
import base64
import os
from flask import Blueprint, request
from cryptography.hazmat.primitives import serialization, hashes

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from repository.load_priv_key import load_private_key
from repository.handlers.create_session_handler import (
    validate_signature,
    check_session_is_valid,
)
from repository.db.db import (
    load_public_key,
    load_sessions,
    create_session,
    load_organizations,
)
from utils.utils import (
    derive_shared_key,
    encrypt_message,
    receive_encrypted_message,
)


# Load the server's private key from a PEM file (done once at startup)
def load_server_private_key():
    current_dir = os.path.dirname(
        os.path.abspath(__file__)
    )  # Get the directory of the current script
    pem_path = os.path.join(
        current_dir, "./rep_priv_key.pem"
    )  # Construct the full path to the PEM file
    with open(pem_path, "rb") as key_file:
        return load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )


# Load the server's private and public keys
server_private_key = load_server_private_key()
server_public_key = server_private_key.public_key()

# Create Flask Blueprint
session = Blueprint("session", __name__, url_prefix="/session")


@session.route("/create", methods=["POST"])
def create_session_controller():
    payload = request.json
    if not payload:
        return {"error": "No payload provided"}, 400

    client_public_key = payload.get("public_key")
    org = payload.get("organization")
    username = payload.get("username")
    signature = payload.get("signature")

    session_id = uuid.uuid4()

    client_public_key = load_public_key(org, client_public_key, username)
    print(f"Client public key: {client_public_key}")

    if not client_public_key:
        return {"error": "Invalid Credentials"}, 404

    if not check_session_is_valid(org, client_public_key):
        return {"error": "Session already exists"}, 400

    public_key_pem = client_public_key

    if not public_key_pem:
        return {"error": "Organization not found"}, 404
    public_key_pem = base64.b64decode(public_key_pem)
    if not public_key_pem:
        return {"error": "Organization not found"}, 404

    public_key = serialization.load_pem_public_key(
        public_key_pem, backend=default_backend()
    )

    if not validate_signature(signature["signature"], signature["message"], public_key):
        return {"error": "Invalid signature"}, 400

    rep_private_key = load_private_key()

    shared_key = derive_shared_key(rep_private_key, public_key_pem)

    session_data = {}

    session_data["shared_key"] = shared_key

    session_data["life_span"] = time.time() + 3600

    session_data["org"] = org

    session_data["client_public_key"] = client_public_key

    create_session(session_id, session_data)

    server_signature = server_private_key.sign(
        str(session_id).encode("utf-8"), ec.ECDSA(hashes.SHA256())
    )

    return {
        "session_id": session_id,
        "server_signature": base64.b64encode(server_signature).decode("utf-8"),
    }


@session.route("/add-role", methods=["POST"])
def add_role_to_session():
    try:
        print(f"Adding role -----------------------------")
        payload = request.json
        sessions = load_sessions()

        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]

        data = receive_encrypted_message(request.json, sessions)

        session_id = payload["session_id"]

        required_fields = ["role"]
        if not all(field in data for field in required_fields):
            return {"error": f"Missing required fields: {required_fields}"}, 400

        role = data["role"]
        user = data["user"]
    
        
        session_data = sessions["sessions"].get(session_id)
        if not session_data:
            return {"error": "Session not found"}, 404

        organization = session_data.get("org")
        if not organization:
            return {"error": "No organization found in session"}, 400

        organizations = load_organizations()
        print(organization)
        
        org_data = next(
            (
                org
                for org in organizations["organizations"]
                if org["name"] == organization
            ),
            None,
        )

        
        
        if not org_data:
            return {"error": f"Organization '{organization}' not found"}, 404

        role_exists = any(r["name"] == role for r in org_data.get("acl", []))
        if not role_exists:
            return {
                "error": f"Role '{role}' does not exist in organization '{organization}'"
            }, 404
            
    
        for org in organizations["organizations"]:
            if org["name"] == organization:
                for subject in org["subject"]: 
                    if subject["username"] == user:
                        if role not in subject["roles"]:
                                return {
                        "error": f"Subject '{user}' can't assume the role '{role}'"
                    }, 400

        for role_to_check in org_data["acl"]:
            if role_to_check["name"] == role:
                if role_to_check["status"] == "inactive":
                    return {
                        "error": f"Role '{role}' is inactive"
                    }, 400
                    
            
             
        if "roles" not in session_data:
            session_data["roles"] = []
        if role not in session_data["roles"]:
            session_data["roles"].append(role)
        else:
            return {"error": f"Role '{role}' already exists in the session"}, 400

        print(f"Updating -----------------------------")

        print(session_data)

        create_session(session_id, session_data)

        print(f"Session data -----------------------------")

        return {
            "message": encrypt_message(
                f"Role '{role}' added to session successfully", shared_key
            ),
        }, 200

    except Exception as e:
        return {"error": str(e)}, 500


@session.route("/remove-role", methods=["POST"])
def remove_role_from_session():
    try:
        payload = request.json
        sessions = load_sessions()

        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]

        data = receive_encrypted_message(request.json, sessions)

        session_id = payload["session_id"]
        if not session_id:
            return (
                encrypt_message({"error": "Invalid or missing session"}, shared_key),
                401,
            )

        required_fields = ["role"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        role = data["role"]

        sessions = load_sessions()
        session_data = sessions["sessions"].get(session_id)
        if not session_data:
            return {"error": "Session not found"}, 404

        organization = session_data.get("org")
        if not organization:
            return {"error": "No organization found in session"}, 400

        organizations = load_organizations()
        org_data = next(
            (
                org
                for org in organizations["organizations"]
                if org["name"] == organization
            ),
            None,
        )
        if not org_data:
            return {"error": f"Organization '{organization}' not found"}, 404

        role_exists = any(r["name"] == role for r in org_data.get("acl", []))
        if not role_exists:
            return (
                encrypt_message(
                    {
                        "error": f"Role '{role}' does not exist in organization '{organization}'"
                    },
                    shared_key,
                ),
                404,
            )

        if "roles" in session_data and role in session_data["roles"]:
            session_data["roles"].remove(role)
        else:
            return (
                encrypt_message(
                    {"error": f"Role '{role}' is not assigned to the current session"},
                    shared_key,
                ),
                400,
            )

        create_session(session_id, session_data)

        return (
            encrypt_message(
                {
                    "message": f"Role '{role}' removed from session successfully",
                    "session": session_data,
                },
                shared_key,
            ),
            200,
        )

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500
