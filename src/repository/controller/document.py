from flask import Blueprint, jsonify, Response, request
from repository.db.db import (
    get_file_content,
    load_organizations,
    save_organizations,
    checkPermission,
    load_sessions,
    add_file,
)
from utils.utils import receive_encrypted_message, encrypt_message

doc = Blueprint("doc", __name__, url_prefix="/doc")


@doc.route("/delete_doc", methods=["POST"])
def deleteDoc():
    sessions = load_sessions()
    session = sessions["sessions"][request.json["session_id"]]
    session_id = request.json["session_id"]
    shared_key = session["shared_key"]


    
    
    
    decrypted_payload = receive_encrypted_message(request.json, sessions)
    if decrypted_payload.get("error", None) != None:
        return (
            encrypt_message({"error": decrypted_payload.get("error")}, shared_key),
            400,
        )

    data = decrypted_payload

    organization = data.get("organization")
    document_name = data.get("document_name")
    session_file = data.get("session_file")
    
    username = session_file["username"]

    permission = "DOC_DELETE"

    if not organization or not document_name:
        return (
            encrypt_message({"error": "No organization found"}, shared_key),
            400,
        )
        
    
    user_roles = session["roles"]
        
    authorized = False
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == organization:  
            for document in org["documents"]: 
                if authorized == True:
                        break
                if document["public-metadata"]["document_name"] == document_name:  
                    for role in document["public-metadata"]["acl"]: 
                        if role["name"] in user_roles and permission in role["permissions"]:
                            authorized = True
                            break 
                    if authorized == True:
                        break
            if authorized == True:
                break

    if authorized:
        for org in organizations["organizations"]:
            if org["name"] == organization:
                for document in org["documents"]:
                    if document["public-metadata"]["document_name"] == document_name:
                        document["public-metadata"]["file_handle"] = "null"
                        document["public-metadata"]["deleter"] = username
                        break
                break
    else:
        return (encrypt_message({"error": "Unauthorized"}, shared_key), 403)

    save_organizations(organizations)

    return (encrypt_message({"message": "Document deleted"}, shared_key), 200)


@doc.route("/file/<file_handle>", methods=["GET"])
def get_file_only(file_handle):
    if not file_handle:
        return jsonify({"error": "The field file_handle is mandatory."}), 400

    file_content = get_file_content(file_handle)
    if not file_content:
        return jsonify({"error": "File not found."}), 404

    try:
        return jsonify({"file_content": file_content}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@doc.route("/metadata", methods=["POST"])
def getDocMetadata():
    """
    Retrieves metadata for a specific document in an organization.
    """
    try:
        sessions = load_sessions()
        session = sessions["sessions"][request.json["session_id"]]
        session_id = request.json["session_id"]
        shared_key = session["shared_key"]

        decrypted_payload = receive_encrypted_message(request.json, sessions)
        if decrypted_payload.get("error", None) != None:
            return (
                encrypt_message({"error": decrypted_payload.get("error")}, shared_key),
                400,
            )
        organizations = load_organizations()

        organization_name = decrypted_payload["organization"]

        if organization_name != session["org"]:
            return (
                encrypt_message(
                    {"error": "No access to this organization"},
                    shared_key,
                ),
                404,
            )
        data = decrypted_payload
        organization_name = data.get("organization")
        document_name = data.get("document_name")
        
        permission = "DOC_READ"

        if not organization_name or not document_name:
            return (
                encrypt_message(
                    {"error": "Both 'organization' and 'document_name' are required."},
                    shared_key,
                ),
                400,
            )
            
        
        user_roles = session["roles"]
        
        authorized = False

        for org in organizations["organizations"]:
            if org["name"] == organization_name:  
                for document in org["documents"]: 
                    if authorized == True:
                            break
                    if document["public-metadata"]["document_name"] == document_name:  
                        for role in document["public-metadata"]["acl"]: 
                            if role["name"] in user_roles and permission in role["permissions"]:
                                authorized = True
                                break 
                        if authorized == True:
                            break
                if authorized == True:
                    break

        organizations = load_organizations()

        if authorized==True:
            for org in organizations["organizations"]:
                if org["name"] == organization_name:
                    for document in org["documents"]:
                        if (
                            document["public-metadata"]["document_name"]
                            == document_name
                        ):
                            return (
                                encrypt_message(
                                    {
                                        "public_metadata": document["public-metadata"],
                                        "private_metadata": document[
                                            "private-metadata"
                                        ],
                                    },
                                    shared_key,
                                ),
                                200,
                            )

            return (
                encrypt_message(
                    {
                        "error": f"Document '{document_name}' not found in organization '{organization_name}'."
                    },
                    shared_key,
                ),
                404,
            )
        else:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@doc.route("/update/acl", methods=["PUT"])
def updateDocACL():
    try:
        sessions = load_sessions()
        session = sessions["sessions"].get(request.json.get("session_id"))
        if not session:
            return encrypt_message({"error": "Invalid session ID"}, None), 400
        shared_key = session["shared_key"]

        decrypted_payload = receive_encrypted_message(request.json, sessions)
        if decrypted_payload.get("error"):
            return encrypt_message({"error": decrypted_payload["error"]}, shared_key), 400

        organization_name = decrypted_payload.get("organization")
        document_name = decrypted_payload.get("document")
        role = decrypted_payload.get("role")
        permission = decrypted_payload.get("permission")
        action = decrypted_payload.get("action")

        if not all([organization_name, document_name, role, permission, action]):
            return encrypt_message({"error": "All fields are mandatory"}, shared_key), 400

        user_roles = session["roles"]
        organizations = load_organizations()
        authorized = False

        for org in organizations["organizations"]:
            if org["name"] == organization_name:
                for document in org["documents"]:
                    if document["public-metadata"]["document_name"] == document_name:
                        for acl_role in document["public-metadata"].get("acl", []):
                            if acl_role["name"] in user_roles and permission in acl_role["permissions"]:
                                authorized = True
                                break
                        if authorized:
                            break
                if authorized:
                    break

        if not authorized:
            return encrypt_message({"error": "Unauthorized"}, shared_key), 403

        for org in organizations["organizations"]:
            if org["name"] == organization_name:
                for document in org["documents"]:
                    if document["public-metadata"]["document_name"] == document_name:
                        acl = document["public-metadata"].get("acl", [])
                        for acl_role in acl:
                            if acl_role["name"] == role:
                                if action == "+":
                                    if permission not in acl_role["permissions"]:
                                        acl_role["permissions"].append(permission)
                                        save_organizations(organizations)
                                        return encrypt_message({"message": "ACL updated"}, shared_key), 200
                                    else:
                                        return encrypt_message({"error": "Permission already exists"}, shared_key), 400
                                elif action == "-":
                                    if permission in acl_role["permissions"]:
                                        acl_role["permissions"].remove(permission)
                                        save_organizations(organizations)
                                        return encrypt_message({"message": "ACL updated"}, shared_key), 200
                                    else:
                                        return encrypt_message({"error": "Permission not found"}, shared_key), 400
                        return encrypt_message({"error": "Role not found"}, shared_key), 404
        return encrypt_message({"error": "Document not found"}, shared_key), 404

    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500


@doc.route("/list", methods=["GET"])
def getAllDocs():
    return


@doc.route("/{id}", methods=["GET"])
def getDocById():
    return


@doc.route("/upload", methods=["POST"])
def uploadDoc():
    return


@doc.route("/download/{id}", methods=["POST"])
def downloadDoc():
    return


@doc.route("/add", methods=["POST"])
def add_file_endpoint():
    try:
        payload = request.json
        sessions = load_sessions()

        session = sessions["sessions"][payload["session_id"]]
        shared_key = session["shared_key"]

        data = receive_encrypted_message(request.json, sessions)

        file_handle = data.get("file_handle")
        file_content = data.get("file_content")

        if not file_handle or not file_content:
            return (
                encrypt_message(
                    {
                        "error": "Estrutura inválida: 'file_handle' e 'file_content' são obrigatórios."
                    },
                    shared_key,
                ),
                400,
            )

        file_data = {
            "file_content": file_content,
        }

        res = add_file(file_handle, file_data)
        return encrypt_message(res, shared_key), 200

    except ValueError as e:
        return encrypt_message({"error": str(e)}, shared_key), 400
    except Exception as e:
        return encrypt_message({"error": str(e)}, shared_key), 500
