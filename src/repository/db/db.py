import json
import os
import base64

ORGANIZATIONS_FILE = "./repository/db/organizations.json"
SESSIONS_FILE = "./repository/db/sessions.json"
FILES_FILE = "./repository/db/files.json"


def load_organizations():
    try:
        if os.path.exists(ORGANIZATIONS_FILE):
            with open(ORGANIZATIONS_FILE, "r") as f:
                data = json.load(f)  # Debugging
                return data
        return {"organizations": []}
    except Exception as e:
        print("Error loading organizations:", e)
        return {"organizations": []}


def load_files():
    try:
        if os.path.exists(FILES_FILE):
            with open(FILES_FILE, "r") as f:
                return json.load(f)["files"]
        return {}
    except Exception as e:
        print("Erro ao carregar arquivos:", e)
        return {}


def create_organization(org):
    if not org:
        raise ValueError("Organization is required.")

    organizations = load_organizations()
    if organizations == {} or "organizations" not in organizations:
        organizations = {"organizations": []}

    for organization in organizations["organizations"]:
        if organization["name"] == org["name"]:
            raise ValueError(f"Organization '{org['name']}' already exists")

    organizations["organizations"].append(org)

    try:
        with open(ORGANIZATIONS_FILE, "w") as f:
            json.dump(organizations, f, indent=4)
            return org
    except Exception as e:
        return {"error": str(e)}


def load_public_key(org, public_key, username):
    organizations = load_organizations()
    for organization in organizations["organizations"]:
        if organization["name"] == org:
            for subject in organization["subject"]:
                if (
                    subject["public_key"] == public_key
                    and subject["username"] == username
                ):
                    return subject["public_key"]
    return None


def create_session(session_id, session):
    """Create a new session in the repository"""
    if not session_id or not session:
        raise ValueError("Session ID and session data are required.")

    session_id = str(session_id)

    if session.get("shared_key") and not isinstance(session["shared_key"], str):
        session["shared_key"] = base64.b64encode(session["shared_key"]).decode("utf-8")

    print(session)

    sessions = load_sessions()
    if sessions == {} or "sessions" not in sessions:
        sessions = {"sessions": {}}

    print("Creating session")
    print(session_id)
    sessions["sessions"][session_id] = session

    print(sessions)

    try:
        with open(SESSIONS_FILE, "w") as f:
            json.dump(sessions, f, indent=4)
            return session
    except Exception as e:
        return {"error": str(e)}


def load_sessions():
    try:
        if os.path.exists(SESSIONS_FILE):
            with open(SESSIONS_FILE, "r") as f:
                data = json.load(f)
                return data
        # Default structure if file does not exist
        return {"sessions": {}}
    except Exception as e:
        return {"sessions": {}}

def save_sessions(sessions):
    try:
        with open(SESSIONS_FILE, "w") as f:
            json.dump(sessions, f, indent=4)
    except Exception as e:
        raise RuntimeError(f"Error saving sessions: {e}")

def add_subject_to_organization(org_name, subject):
    organizations = load_organizations()

    for org in organizations["organizations"]:
        print(f"Checking organization: {org['name']}")  # Debugging
        if org["name"] == org_name:
            if "subject" not in org:
                org["subject"] = []
            # Check for duplicate subjects
            if any(s["username"] == subject["username"] for s in org["subject"]):
                raise ValueError(
                    f"Subject '{subject['username']}' already exists in the organization."
                )
            org["subject"].append(subject)
            save_organizations(organizations)
            return subject

    raise ValueError(f"Organization '{org_name}' not found.")


def get_documents_by_org(org):
    data = load_organizations()
    for organization in data["organizations"]:
        if organization["name"] == org:
            return organization.get("documents", [])
    return None


def suspend_subject_in_organization(org_name, username):
    """
    Sets the `active` property of a subject to False in the specified organization.
    """
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == org_name:
            if "subject" not in org:
                raise ValueError(f"No subjects found in organization '{org_name}'.")

            for subject in org["subject"]:
                if subject["username"] == username:
                    if subject["roles"] != []:
                        print(subject["roles"])
                        for role in subject["roles"]:
                            if role == "manager":
                                raise ValueError(
                                    f"Cannot suspend subject '{username}' because it has the 'manager' role."
                                )

                    subject["active"] = False
                    save_organizations(organizations)
                    return subject

            raise ValueError(
                f"Subject '{username}' not found in organization '{org_name}'."
            )

    raise ValueError(f"Organization '{org_name}' not found.")


def activate_subject_in_organization(org_name, username):
    """
    Sets the `active` property of a subject to True in the specified organization.
    """
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == org_name:
            if "subject" not in org:
                raise ValueError(f"No subjects found in organization '{org_name}'.")

            for subject in org["subject"]:
                if subject["username"] == username:
                    subject["active"] = True
                    save_organizations(organizations)
                    return subject

            raise ValueError(
                f"Subject '{username}' not found in organization '{org_name}'."
            )

    raise ValueError(f"Organization '{org_name}' not found.")


def save_files(files_data):
    try:
        with open(FILES_FILE, "w") as f:
            json.dump({"files": files_data}, f, indent=4)
    except Exception as e:
        raise RuntimeError(f"Erro ao salvar arquivos: {e}")


def add_file(file_handle, file_data):
    try:
        files_data = load_files()

        if file_handle in files_data:
            raise ValueError(f"O identificador '{file_handle}' já existe.")

        # Adiciona o novo arquivo com sua estrutura
        files_data[file_handle] = file_data

        save_files(files_data)
        return {"message": "Arquivo adicionado com sucesso."}
    except Exception as e:
        raise RuntimeError(f"Erro ao adicionar arquivo: {e}")


def get_file_content(file_handle):
    files_data = load_files()
    file_entry = files_data.get(file_handle)
    if file_entry:
        return file_entry.get("file_content")
    return None


def save_organizations(organizations):
    try:
        with open(ORGANIZATIONS_FILE, "w") as f:
            json.dump(organizations, f, indent=4)
    except Exception as e:
        raise RuntimeError(f"Error saving organizations: {e}")


def add_role_to_organization(org_name, role):
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == org_name:
            if "acl" not in org:
                org["acl"] = []
            if any(r["name"] == role["name"] for r in org["acl"]):
                raise ValueError(
                    f"Role '{role['name']}' already exists in the organization."
                )
            org["acl"].append(role)
            save_organizations(organizations)
            return role

    raise ValueError(f"Organization '{org_name}' not found.")


def add_role_to_subject_in_organization(org_name, username, role_name):
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == org_name:
            if "subject" not in org:
                raise ValueError(f"No subjects found in organization '{org_name}'.")

            for subject in org["subject"]:
                if subject["username"] == username:
                    if "roles" not in subject:
                        subject["roles"] = []

                    if role_name in subject["roles"]:
                        raise ValueError(
                            f"Role '{role_name}' is already assigned to subject '{username}'."
                        )

                    if "acl" not in org or not any(
                        r["name"] == role_name for r in org["acl"]
                    ):
                        raise ValueError(
                            f"Role '{role_name}' does not exist in organization '{org_name}'."
                        )

                    subject["roles"].append(role_name)
                    save_organizations(organizations)
                    return subject

            raise ValueError(
                f"Subject '{username}' not found in organization '{org_name}'."
            )

    raise ValueError(f"Organization '{org_name}' not found.")


def remove_role_from_subject_in_organization(org_name, username, role_name):
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == org_name:
            if "subject" not in org:
                raise ValueError(f"No subjects found in organization '{org_name}'.")

            for subject in org["subject"]:
                if subject["username"] == username:
                    if "roles" not in subject or role_name not in subject["roles"]:
                        raise ValueError(
                            f"Role '{role_name}' is not assigned to subject '{username}'."
                        )

                    subject["roles"].remove(role_name)
                    save_organizations(organizations)
                    return subject

            raise ValueError(
                f"Subject '{username}' not found in organization '{org_name}'."
            )

    raise ValueError(f"Organization '{org_name}' not found.")


def add_subject_to_role_in_organization(org_name, username, role_name):
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == org_name:
            if "acl" not in org:
                raise ValueError(f"No acl found in organization '{org_name}'.")

            for role in org["acl"]:
                if role["name"] == role_name:
                    if "subjects" not in role:
                        role["subjects"] = []

                    if username in role["subjects"]:
                        raise ValueError(
                            f"Subject '{username}' is already in role '{role_name}'."
                        )
                    role["subjects"].append(username)
                    save_organizations(organizations)
                    return role

            raise ValueError(
                f"Role '{role_name}' not found in organization '{org_name}'."
            )

    raise ValueError(f"Organization '{org_name}' not found.")


def remove_subject_from_role_in_organization(org_name, username, role_name):
    organizations = load_organizations()

    for org in organizations["organizations"]:
        if org["name"] == org_name:
            if "acl" not in org:
                raise ValueError(f"No acl found in organization '{org_name}'.")

            for role in org["acl"]:
                if role["name"] == role_name:
                    if "subjects" not in role or username not in role["subjects"]:
                        raise ValueError(
                            f"Subject '{username}' is not in role '{role_name}'."
                        )

                    role["subjects"].remove(username)
                    save_organizations(organizations)
                    return role

            raise ValueError(
                f"Role '{role_name}' not found in organization '{org_name}'."
            )

    raise ValueError(f"Organization '{org_name}' not found.")


def checkPermission(session_id, permissions, organization, organizations):
    with open(SESSIONS_FILE, "r") as f:
        sessions = json.load(f)

    session_data = sessions["sessions"].get(session_id)
    if not session_data:
        print("Session not found")
        return False

    user_roles = session_data.get("roles", [])
    if not user_roles:
        print("No roles found in session")
        return False

    print("User roles:", user_roles)

    for org in organizations["organizations"]:
        if org["name"] == organization:
            for role_name in user_roles:
                for role_ite in org.get("acl", []):
                    if (
                        role_ite["name"] == role_name
                        and role_ite.get("status", "").lower() == "active"
                    ):
                        if all(
                            permission in role_ite["permissions"]
                            for permission in permissions
                        ):
                            print(role_name)
                            return True

            print("No active role with required permissions found")
            return False

    print("Organization not found")
    return False


def getFirstActiveRole(session_id, organization_name, organizations):
    with open(SESSIONS_FILE, "r") as f:
        sessions = json.load(f)

    session_data = sessions["sessions"].get(session_id)
    if not session_data:
        print("Session not found")
        return None

    roles = session_data.get("roles", [])
    if not roles:
        print("No roles found for session")
        return None

    for org in organizations["organizations"]:
        if org["name"] == organization_name:
            for role_name in roles:
                for role in org.get("roles", []):
                    if role["name"] == role_name and role.get("status") == "active":
                        return role["name"]

            print("Active role not found in organization")
            return None

    print("Organization not found")
    return None
