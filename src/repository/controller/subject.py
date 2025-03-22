from flask import Blueprint, request, jsonify
from requests import session
from repository.db.db import (
    load_organizations,
    load_sessions,
    save_sessions,
    add_role_to_subject_in_organization,
    add_subject_to_organization,
    suspend_subject_in_organization,
    activate_subject_in_organization,
    checkPermission,
    add_subject_to_role_in_organization,
    remove_role_from_subject_in_organization,
    remove_subject_from_role_in_organization,
)
from utils.utils import receive_encrypted_message, encrypt_message, decrypt_message
import os


subject = Blueprint("subject", __name__, url_prefix="/subject")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ORGANIZATIONS_FILE = os.path.join(BASE_DIR, "../../../organizations.json")
KEYS_DIR = os.path.join(BASE_DIR, "../../../keys")


@subject.route("/create", methods=["POST"])
def create_subject():
    """
    Endpoint to add a subject to an organization with permission checking.
    """
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

        required_fields = ["organization", "username", "name", "email", "public_key"]

        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        organizations = load_organizations()
        permissions = ["SUBJECT_NEW"]
        

        print("Checking permissions")
        print( data["organization"])

        authorized = checkPermission(
            session_id, permissions, data["organization"], organizations
        )
        
        if authorized == False:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        subject_data = {
            "username": data["username"],
            "name": data["name"],
            "email": data["email"],
            "public_key": data["public_key"],
            "active": True,
            "roles": [],
        }
        added_subject = add_subject_to_organization(data["organization"], subject_data)

        return (
            encrypt_message(
                {"message": "Subject added successfully", "subject": added_subject},
                shared_key,
            ),
            201,
        )

    except ValueError as ve:
        print(ve)
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(e)

        return jsonify({"error": str(e)}), 500


@subject.route("/list", methods=["GET"])
def list_subjects():
    """
    Endpoint to list all subjects in an organization.
    """
    try:
        org_name = request.args.get("organization")
        if not org_name:
            return jsonify({"error": "Organization name is required"}), 400

        # Load organizations
        organizations = load_organizations()

        # Find the organization
        for org in organizations["organizations"]:
            if org["name"] == org_name:
                return jsonify({"subject": org.get("subject", [])}), 200

        return jsonify({"error": f"Organization '{org_name}' not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@subject.route("/suspend", methods=["POST"])
def suspend_subject():
    try:
        data = request.json
        session_id = request.headers.get("Session-ID")
        organizations = load_organizations()
        organization = data.get("organization")
        permissions = ["SUBJECT_DOWN"]

        if not session_id:
            return jsonify({"error": "Invalid or missing session"}), 401

        required_fields = ["organization", "username"]
        if not all(field in data for field in required_fields):
            return (
                jsonify({"error": f"Missing required fields: {required_fields}"}),
                400,
            )

        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )
        if authorized:
            subject_data = suspend_subject_in_organization(
                data["organization"], data["username"]
            )
        else:
            return jsonify({"error": "Unauthorized"}), 403

        return (
            jsonify(
                {"message": "Subject suspended successfully", "subject": subject_data}
            ),
            200,
        )

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@subject.route("/activate", methods=["POST"])
def activate_subject():
    try:
        payload = request.json
        sessions = load_sessions()

        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]

        data = receive_encrypted_message(request.json, sessions)
        organizations = load_organizations()
        organization = data.get("organization")
        permissions = ["SUBJECT_UP"]

        session_id = payload["session_id"]
        if not session_id:
            return (
                encrypt_message({"error": "Invalid or missing session"}, shared_key),
                401,
            )

        required_fields = ["organization", "username"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )

        if authorized:
            subject_data = activate_subject_in_organization(
                data["organization"], data["username"]
            )
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        return (
            encrypt_message(
                {"message": "Subject activated successfully", "subject": subject_data},
                shared_key,
            ),
            200,
        )

    except ValueError as ve:
        return encrypt_message({"error": str(ve)}, shared_key), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@subject.route("/add-role", methods=["POST"])
def add_role_to_subject():
    try:
        payload = request.json
        sessions = load_sessions()

        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]

        data = receive_encrypted_message(request.json, sessions)

        session_id = payload["session_id"]
        permissions = ["ROLE_MOD"]
        if not session_id:
            return (
                encrypt_message({"error": "Invalid or missing session"}, shared_key),
                401,
            )

        required_fields = ["organization", "username", "role"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        organizations = load_organizations()
        organization = data.get("organization")

        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )

        if authorized:
            updated_subject = add_role_to_subject_in_organization(
                data["organization"], data["username"], data["role"]
            )

            updated_role = add_subject_to_role_in_organization(
                data["organization"], data["username"], data["role"]
            )
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        return (
            encrypt_message(
                {
                    "message": "Role assigned successfully",
                    "subject": updated_subject,
                    "role": updated_role,
                },
                shared_key,
            ),
            200,
        )

    except ValueError as ve:
        return encrypt_message({"error": str(ve)}, shared_key), 400
    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@subject.route("/remove-role", methods=["POST"])
def remove_role_from_subject():
    try:
        payload = request.json
        if not isinstance(payload, dict):
            return {"error": "Invalid Payload, must be a JSON"}, 400


        session_id = payload.get("session_id")
        if not session_id:
            return {"error": "Session ID is mandatory"}, 401

        sessions = load_sessions()
        session = sessions["sessions"].get(session_id)
        if not session:
            return {"error": "Invalid Session"}, 403

        shared_key = session["shared_key"]
        

        data = receive_encrypted_message(request.json, sessions)
        if not isinstance(data, dict):
            return encrypt_message({"error": "Error at decrypt or bad format"}, shared_key), 400

        required_fields = ["organization", "username", "role"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return encrypt_message(
                {"error": f"Some mandatory fields empty: {', '.join(missing_fields)}"},
                shared_key,
            ), 400

        organization_name = data["organization"]
        username = data["username"]
        role = data["role"]


        permissions = ["ROLE_MOD"]
        organizations = load_organizations()
        authorized = checkPermission(session_id, permissions, organization_name, organizations)

        if not authorized:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403


        for session_data in sessions["sessions"].values():
            if "roles" in session_data and role in session_data["roles"]:
                session_data["roles"].remove(role)
        save_sessions(sessions)


        updated_subject = remove_role_from_subject_in_organization(organization_name, username, role)
        updated_role = remove_subject_from_role_in_organization(organization_name, username, role)


        return encrypt_message(
            {
                "message": "Role removed successfully",
                "subject": updated_subject,
                "role": updated_role,
            },
            shared_key,
        ), 200

    except ValueError as ve:
        return encrypt_message({"error": str(ve)}, shared_key), 400
    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@subject.route("/roles", methods=["GET"])
def list_subject_roles():
    sessions = load_sessions()
    session_id = request.json["session_id"]
    session = sessions["sessions"][request.json["session_id"]]
    shared_key = session["shared_key"]
    try:
        decrypted_payload = receive_encrypted_message(request.json, sessions)
        if decrypted_payload.get("error", None) != None:
            return (
                encrypt_message({"error": decrypted_payload.get("error")}, shared_key),
                400,
            )

        organization = decrypted_payload["organization"]
        username = decrypted_payload["username"]

        if not session_id:
            return (encrypt_message({"error": "No session_id"}, shared_key), 400)

        if not organization or not username:
            return (
                encrypt_message({"error": "No organization found"}, shared_key),
                404,
            )
        if organization != session["org"]:
            return (
                encrypt_message(
                    {"error": "No access to this organization"}, shared_key
                ),
                404,
            )

        organizations = load_organizations()
        for org in organizations["organizations"]:
            if org["name"] == organization:
                for subject in org.get("subject", []):
                    if subject["username"] == username:
                        roles = subject.get("roles", [])
                        return encrypt_message({"roles": roles}, shared_key), 200

                return (
                    encrypt_message(
                        {"error": "Subject not found in organization"}, shared_key
                    ),
                    404,
                )

        return (
            encrypt_message({"error": "No organization found"}, shared_key),
            400,
        )

    except Exception as e:
        return (encrypt_message({"error": e}, shared_key), 400)


