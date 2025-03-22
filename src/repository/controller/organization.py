from flask import Blueprint, request, jsonify
from repository.db.db import (
    load_organizations,
    create_organization,
    get_documents_by_org,
    save_organizations,
    checkPermission
)
from flask_cors import cross_origin
import os
from utils.utils import (
    receive_encrypted_message,
    encrypt_message,
    load_public_key,
    deserialize_public_key,
)
from repository.db.db import load_sessions


org = Blueprint("orgs", __name__, url_prefix="/org")


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ORGANIZATIONS_FILE = os.path.join(BASE_DIR, "../../../organizations.json")
KEYS_DIR = os.path.join(BASE_DIR, "../../../keys")

PERMISSIONS = [
    "DOC_ACL",
    "DOC_READ",
    "DOC_NEW",
    "DOC_DELETE",
    "ROLE_ACL",
    "ROLE_NEW",
    "ROLE_DOWN",
    "ROLE_UP",
    "ROLE_MOD",
    "SUBJECT_DOWN",
    "SUBJECT_UP",
    "SUBJECT_NEW",
]


@org.route("/", methods=["GET"])
@cross_origin()
def getAllOrgs():
    return load_organizations()["organizations"]


@org.route("/<organization>", methods=["GET"])
def getDocByOrg(organization):
    sessions = load_sessions()
    session = sessions["sessions"][request.json["session_id"]]
    shared_key = session["shared_key"]
    rep_pub_key = load_public_key("rep_pub_key.pem")
    rep_pub_key = deserialize_public_key(rep_pub_key)
    try:
        if not organization:
            return jsonify({"error": "The organization is required."}), 400

        if organization != session["org"]:
            return (
                encrypt_message(
                    {"error": "No access to this organization"}, shared_key, rep_pub_key
                ),
                404,
            )

        documents = {"documents": get_documents_by_org(organization)}

        print(f"documents: {documents}")

        if not documents:
            return (
                encrypt_message({"error": "no documents found"}, shared_key),
                404,
            )
        payload = encrypt_message(documents, shared_key)

        return jsonify(payload), 200

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@org.route("/<organization>/add_doc", methods=["POST"])
def add_doc_to_organization(organization):
    try:
        payload = request.json
        sessions = load_sessions()
        
        print(payload)
        
        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]
        
        session_id = payload["session_id"]
        
        
        data = receive_encrypted_message(request.json, sessions)

        organizations = load_organizations()

        print("data", data)
        
        permissions = ["DOC_NEW"]

        print("Checking permissions")

        user = data["public-metadata"]["creator"]

        org = next(
            (
                org
                for org in organizations["organizations"]
                if org["name"] == organization
            ),
            None,
        )
        if not org:
            return (
                encrypt_message(
                    {"error": f"Organization '{organization}' not found."}, shared_key
                ),
                404,
            )        
        
        authorized = checkPermission(session_id, permissions, organization, organizations)
        
        if not authorized:
            return encrypt_message({"error": "Unauthorized1"}, shared_key), 403
        required_keys = ["public-metadata", "private-metadata"]
        
        if not all(key in data for key in required_keys):
            return (
                encrypt_message({"error": "Invalid document structure."}, shared_key),
                400,
            )

        for document in org["documents"]:
            print(document["public-metadata"]["document_name"])
            if (
                document["public-metadata"]["document_name"]
                == data["public-metadata"]["document_name"]
            ):
                return (
                    encrypt_message({"error": "Document already exists."}, shared_key),
                    400,
                )
                
        role_to_sign = None        
                
        for org in organizations["organizations"]:
            if org["name"] == organization:
                for role in org["acl"]:
                    if user in role["subjects"] and role["status"] == "active":
                        role_to_sign = role["name"]
        
                                        
        if role_to_sign == None:
            return (
                encrypt_message({"error": "Unauthorized2"}, shared_key),
                403,
            )
        data_to_sign = {
                            "name": role_to_sign,
                            "permissions":["DOC_READ","DOC_ACL","DOC_DELETE"]
                        }
        
        for role_to_add in org["acl"]:
            if role_to_add["name"] == role_to_sign:
                for permission in data_to_sign["permissions"]:
                    if permission not in role_to_add["permissions"]:
                        role_to_add["permissions"].append(permission)
        
        
                
        data["public-metadata"]["acl"].append(data_to_sign)

        org["documents"].append(data)

        save_organizations(organizations)

        return (
            encrypt_message({"message": "Document added successfully."}, shared_key),
            200,
        )

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@org.route("/<organization>/del_doc/<document_name>", methods=["DELETE"])
def del_doc_from_organization(organization, document_name):
    try:
        payload = request.json
        sessions = load_sessions()

        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]

        data = receive_encrypted_message(request.json, sessions)
        organizations = load_organizations()

        org = next(
            (
                org
                for org in organizations["organizations"]
                if org["name"] == organization
            ),
            None,
        )
        if not org:
            return (
                encrypt_message(
                    {"error": f"Organization '{organization}' not found."}, shared_key
                ),
                404,
            )

        org["documents"] = [
            doc
            for doc in org["documents"]
            if doc["public-metadata"]["document_name"] != document_name
        ]

        save_organizations(organizations)

        return (
            encrypt_message({"message": "Document deleted successfully."}, shared_key),
            200,
        )

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@org.route("/", methods=["POST"])
def createOrg():
    args = request.json
    print("args", args)
    if not args:
        raise ValueError("Nenhum argumento foi pass")

    org = args.get("org")
    username = args.get("username")
    name = args.get("name")
    email = args.get("email")
    public_key = args.get("public_key")

    if not all([org, username, name, email, public_key]):
        raise ValueError(
            "Todos os campos (org, username, name, email) são obrigatórios."
        )

    org = {
        "name": org,
        "subject": [
            {
                "username": username,
                "name": name,
                "email": email,
                "public_key": public_key,
                "active": True,
                "roles": ["manager"],
            },
        ],
        "documents": [],
        "acl": [
            {
                "name": "manager",
                "permissions": PERMISSIONS,
                "subjects": [username],
                "status": "active",
            }
        ],
    }

    result = create_organization(org)

    return result


@org.route("/subjects", methods=["GET"])
def getSubjects():
    """
    Endpoint to list all subjects in an organization. Optionally filters by username.
    """
    try:
        # Retrieve the organization name and optional username from query parameters
        sessions = load_sessions()
        session = sessions["sessions"][request.json["session_id"]]
        shared_key = session["shared_key"]

        decrypted_payload = receive_encrypted_message(request.json, sessions)

        if decrypted_payload.get("error", None) != None:
            return (
                encrypt_message({"error": decrypted_payload.get("error")}, shared_key),
                400,
            )

        organizations = load_organizations()

        print(decrypted_payload)

        org_name = decrypted_payload["organization"]

        username = decrypted_payload["username"]

        if not org_name:
            return (
                encrypt_message({"error": "No organization found"}, shared_key),
                400,
            )

        # Find the matching organization and list its subjects
        for org in organizations["organizations"]:
            if org["name"] == org_name:
                subjects = org.get("subject", [])

                # Filter subjects by username if provided
                if username:
                    subjects = [s for s in subjects if s.get("username") == username]

                return encrypt_message({"subjects": subjects}, shared_key), 200

        # If the organization is not found, return an error
        return (
            encrypt_message({"error": "No organization found"}, shared_key),
            404,
        )

    except Exception as e:
        # Handle unexpected errors gracefully
        return (
            encrypt_message({"error": e}, shared_key),
            400,
        )


@org.route("/<organization>/roles", methods=["GET"])
def getRoles(organization):
    """
    Endpoint to list all roles in an organization.
    """
    try:
        if not organization:
            return jsonify({"error": "The organization is required."}), 400

        sessions = load_sessions()

        session = sessions["sessions"][request.json["session_id"]]
        shared_key = session["shared_key"]

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
                roles = org.get("acl", [])

                return encrypt_message({"acl": roles}, shared_key), 200

        return (
            encrypt_message({"error": "No organization found"}, shared_key),
            404,
        )

    except Exception as e:
        return (
            encrypt_message({"error": str(e)}, shared_key),
            404,
        )
