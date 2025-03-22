from flask import Blueprint, request, jsonify
from repository.db.db import (
    add_role_to_organization,
    load_organizations,
    save_organizations,
    load_sessions,
    checkPermission,
)
from utils.utils import receive_encrypted_message, encrypt_message

import os


role = Blueprint("role", __name__, url_prefix="/role")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ORGANIZATIONS_FILE = os.path.join(BASE_DIR, "../../../organizations.json")
KEYS_DIR = os.path.join(BASE_DIR, "../../../keys")


role = Blueprint("role", __name__, url_prefix="/role")


@role.route("/create", methods=["POST"])
def create_role():
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
        required_fields = ["organization", "name"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        organization = data["organization"]
        organizations = load_organizations()

        permissions = ["ROLE_NEW"]

        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )

        role_data = {
            "name": data["name"],
            "permissions": [],
            "subjects": [],
            "status": "active",
        }

        if authorized:
            added_role = add_role_to_organization(data["organization"], role_data)
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        return (
            encrypt_message(
                {"message": "Role added successfully", "role": added_role}, shared_key
            ),
            201,
        )

    except ValueError as ve:
        return encrypt_message({"error": str(ve)}, shared_key), 400
    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@role.route("/subjects", methods=["GET"])
def list_role_subjects():
    """
    Endpoint to list all subjects in a given role for an organization.
    """
    sessions = load_sessions()
    session = sessions["sessions"][request.json["session_id"]]
    shared_key = session["shared_key"]
    try:
        session_id = request.json["session_id"]
        organizations = load_organizations()

        if not session_id:
            return jsonify({"error": "Invalid or missing session"}), 401

        decrypted_payload = receive_encrypted_message(request.json, sessions)
        if decrypted_payload.get("error", None) != None:
            return (
                encrypt_message({"error": decrypted_payload.get("error")}, shared_key),
                400,
            )
        org = decrypted_payload["organization"]
        role = decrypted_payload["role"]

        if org != session["org"]:
            return (
                encrypt_message(
                    {"error": "No access to this organization"}, shared_key
                ),
                404,
            )

        organization = org
        role_name = role

        for org in organizations["organizations"]:
            if org["name"] == organization:
                for role in org.get("acl", []):
                    if role["name"] == role_name:
                        subjects = role.get("subjects", [])
                        return (
                            encrypt_message({"subjects": subjects}, shared_key),
                            200,
                        )

                return (
                    encrypt_message(
                        {"error": f"Role not found in: {org['name']}"}, shared_key
                    ),
                    404,
                )

        return (
            encrypt_message({"error": "no organization found"}, shared_key),
            404,
        )

    except Exception as e:
        return (
            encrypt_message({"error": e}, shared_key),
            404,
        )


@role.route("/permissions", methods=["GET"])
def list_role_permissions():
    """
    Endpoint to list all permissions of a given role in an organization.
    """
    sessions = load_sessions()
    session_id = request.json["session_id"]
    session = sessions["sessions"][request.json["session_id"]]
    shared_key = session["shared_key"]
    try:
        # Extract query parameters
        decrypted_payload = receive_encrypted_message(request.json, sessions)
        if decrypted_payload.get("error", None) != None:
            return (
                encrypt_message({"error": decrypted_payload.get("error")}, shared_key),
                400,
            )

        organization = decrypted_payload["organization"]
        role_name = decrypted_payload["role"]

        if not session_id:
            return (encrypt_message({"error": "No session_id"}, shared_key), 400)

        if not organization or not role_name:
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
                print(f"org: {organization}")

                for role in org.get("acl", []):
                    if role["name"] == role_name:
                        permissions = role.get("permissions", [])
                        return (
                            encrypt_message({"permissions": permissions}, shared_key),
                            200,
                        )

                return (
                    encrypt_message({"error": "No organization found"}, shared_key),
                    404,
                )

        return (
            encrypt_message({"error": "No organization found"}, shared_key),
            400,
        )

    except Exception as e:
        return (encrypt_message({"error": e}, shared_key), 400)


@role.route("/permission-roles", methods=["GET"])
def list_roles_with_permission():
    """
    Endpoint to list all roles that have a specific permission in an organization.
    """
    sessions = load_sessions()
    session_id = request.json["session_id"]
    session = sessions["sessions"][request.json["session_id"]]
    shared_key = session["shared_key"]
    try:
        # Extract query parameters
        decrypted_payload = receive_encrypted_message(request.json, sessions)
        if decrypted_payload.get("error", None) != None:
            return (
                encrypt_message({"error": decrypted_payload.get("error")}, shared_key),
                400,
            )

        organization = decrypted_payload["organization"]
        permission = decrypted_payload["permission"]

        if not session_id:
            return (encrypt_message({"error": "No session_id"}, shared_key), 400)

        if not organization or not permission:
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
                print(f"organization {org}")
                roles_with_permission = [
                    role["name"]
                    for role in org.get("acl", [])
                    if permission in role.get("permissions", [])
                ]
                return (
                    encrypt_message({"acl": roles_with_permission}, shared_key),
                    200,
                )

        return (
            encrypt_message({"error": "No organization found"}, shared_key),
            404,
        )

    except Exception as e:
        return (
            encrypt_message({"error": e}, shared_key),
            404,
        )


@role.route("/suspend", methods=["POST"])
def suspend_role():
    try:
        payload = request.json
        sessions = load_sessions()

        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]

        data = receive_encrypted_message(payload, sessions)

        session_id = payload["session_id"]

        if not session_id:
            return (
                encrypt_message({"error": "Invalid or missing session"}, shared_key),
                401,
            )

        required_fields = ["organization", "role_name"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        organization = data["organization"]
        role_name = data["role_name"]
        permissions = ["ROLE_DOWN"]

        organizations = load_organizations()
        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )

        if authorized:
            for org in organizations["organizations"]:
                if org["name"] == organization:
                    for role in org.get("acl", []):
                        if role["name"] == role_name:
                            if role["status"] == "inactive":
                                return (
                                    encrypt_message(
                                        {
                                            "error": f"Role '{role_name}' is already suspended."
                                        },
                                        shared_key,
                                    ),
                                    400,
                                )
                            if role["name"] == "manager":
                                return (
                                    encrypt_message(
                                        {
                                            "error": f"Role '{role_name}' cannot be suspended."
                                        },
                                        shared_key,
                                    ),
                                    400,
                                )
                            role["status"] = "inactive"
                            save_organizations(organizations)
                            return (
                                encrypt_message(
                                    {
                                        "message": f"Role '{role_name}' suspended successfully."
                                    },
                                    shared_key,
                                ),
                                200,
                            )

                    return (
                        encrypt_message(
                            {
                                "error": f"Role '{role_name}' not found in organization '{organization}'."
                            },
                            shared_key,
                        ),
                        404,
                    )
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        return (
            encrypt_message(
                {"error": f"Organization '{organization}' not found."}, shared_key
            ),
            404,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@role.route("/reactivate", methods=["POST"])
def reactivate_role():
    """
    Endpoint to reactivate a role in an organization by changing its status to 'active'.
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
        required_fields = ["organization", "role_name"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        organization = data["organization"]
        role_name = data["role_name"]
        permissions = ["ROLE_UP"]

        organizations = load_organizations()
        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )

        if authorized:
            for org in organizations["organizations"]:
                if org["name"] == organization:
                    for role in org.get("acl", []):
                        if role["name"] == role_name:
                            role["status"] = "active"
                            save_organizations(organizations)
                            return (
                                encrypt_message(
                                    {
                                        "message": f"Role '{role_name}' reactivated successfully."
                                    },
                                    shared_key,
                                ),
                                200,
                            )

                    return (
                        encrypt_message(
                            {
                                "error": f"Role '{role_name}' not found in organization '{organization}'."
                            },
                            shared_key,
                        ),
                        404,
                    )
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        return (
            encrypt_message(
                {"error": f"Organization '{organization}' not found."}, shared_key
            ),
            404,
        )

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@role.route("/add-permission", methods=["POST"])
def add_permission():
    """
    Endpoint to add a permission to a role.
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
        required_fields = ["organization", "role_name", "permission"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        organization = data["organization"]
        role_name = data["role_name"]
        permission = data["permission"]

        permissions = ["ROLE_MOD"]

        print("organization")

        organizations = load_organizations()
        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )

        if authorized:
            for org in organizations["organizations"]:
                if org["name"] == organization:
                    for role in org.get("acl", []):
                        if role["name"] == role_name:
                            if "permissions" not in role:
                                role["permissions"] = []
                            if permission not in role["permissions"]:
                                role["permissions"].append(permission)
                            else:
                                return (
                                    encrypt_message(
                                        {
                                            "error": f"Permission '{permission}' already exists in role '{role_name}'."
                                        },
                                        shared_key,
                                    ),
                                    400,
                                )

                            save_organizations(organizations)
                            return (
                                encrypt_message(
                                    {
                                        "message": f"Permission '{permission}' successfully added to role '{role_name}'."
                                    },
                                    shared_key,
                                ),
                                200,
                            )

                    return (
                        encrypt_message(
                            {
                                "error": f"Role '{role_name}' not found in organization '{organization}'."
                            },
                            shared_key,
                        ),
                        404,
                    )

            return (
                encrypt_message(
                    {"error": f"Organization '{organization}' not found."}, shared_key
                ),
                404,
            )
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@role.route("/remove-permission", methods=["POST"])
def remove_permission():
    """
    Endpoint to remove a permission from a role.
    """
    try:
        # Extract request data
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

        required_fields = ["organization", "role_name", "permission"]
        if not all(field in data for field in required_fields):
            return (
                encrypt_message(
                    {"error": f"Missing required fields: {required_fields}"}, shared_key
                ),
                400,
            )

        organization = data["organization"]
        role_name = data["role_name"]
        permission = data["permission"]
        permissions = ["ROLE_MOD"]

        organizations = load_organizations()
        authorized = checkPermission(
            session_id, permissions, organization, organizations
        )
        
       

        if authorized:
            for org in organizations["organizations"]:
                if org["name"] == organization:
                    for role in org.get("acl", []):
                        if role["name"] == role_name:
                            if (
                                "permissions" not in role
                                or permission not in role["permissions"]
                            ):
                                return (
                                    encrypt_message(
                                        {
                                            "error": f"Permission '{permission}' not found in role '{role_name}'."
                                        },
                                        shared_key,
                                    ),
                                    404,
                                )
                            role["permissions"].remove(permission)
                            save_organizations(organizations)
                            return (
                                encrypt_message(
                                    {
                                        "message": f"Permission '{permission}' removed from role '{role_name}' successfully."
                                    },
                                    shared_key,
                                ),
                                200,
                            )

                    return (
                        encrypt_message(
                            {
                                "error": f"Role '{role_name}' not found in organization '{organization}'."
                            },
                            shared_key,
                        ),
                        404,
                    )
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        return (
            encrypt_message(
                {"error": f"Organization '{organization}' not found."}, shared_key
            ),
            404,
        )

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500
