#!/bin/bash

# Variables
ORG_NAME="Test Organization"
SUBJECT="admin"
SUBJECT_NAME="Admin User"
SUBJECT_EMAIL="admin@test.org"
PASSWORD="123"
CREDENTIALS_FILE="../credentials.json"
SESSION_FILE="../session/session.json"
DOCUMENT_NAME="document_one"
DOCUMENT_PATH="document_one.txt"
OUTPUT_FILE="output_document.txt"
METADATA_FILE="metadata.json"
ENCRYPTED_FILE="output_document.txt"

REGULAR_USER="new_user"
REGULAR_USER_NAME="New User"
REGULAR_USER_EMAIL="new@email.com"
REGULAR_CREDS_FILE="../new_user_credentials.json"
REGULAR_SESSION_FILE="../new_user_session.json"
REGULAR_PASSWORD="123"
TEST_ROLE="test_role"

check_command() {
    if [ $? -ne 0 ]; then
        echo "Error"
        exit 1
    fi
}

cd src || {
    echo "Error: src directory not found."
    exit 1
}

echo "Starting server..."
docker-compose up -d


cd ./client

cd ./subject || {
    echo "Error: subject directory not found."
    exit 1
}

./rep_subject_credentials "$PASSWORD" "$CREDENTIALS_FILE"
check_command

./rep_subject_credentials "$REGULAR_USER" "$REGULAR_CREDS_FILE"
check_command

cd ../organization || {
    echo "Error: organization directory not found."
    exit 1
}
./rep_create_org "$ORG_NAME" "$SUBJECT" "$SUBJECT_NAME" "$SUBJECT_EMAIL" "$CREDENTIALS_FILE"
check_command

./rep_list_orgs
check_command

cd ../session || {
    echo "Error: session directory not found."
    exit 1
}
./rep_create_session "$ORG_NAME" "$SUBJECT" "$PASSWORD" "$CREDENTIALS_FILE" "$SESSION_FILE"
check_command

cd ../role || {
    echo "Error: role directory not found."
    exit 1
}

./rep_assume_role "$SESSION_FILE" "manager"
check_command

cd ../subject || exit 1
echo "Manager adding regular user..."
./rep_add_subject "$SESSION_FILE" "$REGULAR_USER" "$REGULAR_USER_NAME" "$REGULAR_USER_EMAIL" "$REGULAR_CREDS_FILE"
check_command 


cd ../document || {
    echo "Error: document directory not found."
    exit 1
}
./rep_add_doc "$SESSION_FILE" "$DOCUMENT_NAME" "$DOCUMENT_PATH"
check_command

./rep_get_doc_file "$SESSION_FILE" "$DOCUMENT_NAME" "$OUTPUT_FILE"
check_command


cd ../subject || {
    echo "Error: subject directory not found."
    exit 1
}

cd ../organization || {
    echo "Error: organization directory not found."
    exit 1
}
./rep_list_subjects "$SESSION_FILE"
check_command

cd ../document || {
    echo "Error: document directory not found."
    exit 1
}
echo "Adding metadata..."
./rep_get_doc_metadata "$SESSION_FILE" "$DOCUMENT_NAME"
check_command

file_handle=$(jq -r '.public_metadata.file_handle' "$METADATA_FILE")

./rep_get_file "$file_handle" "$OUTPUT_FILE"
check_command

echo "Listing docs"
./rep_list_docs "$SESSION_FILE" "-s $SUBJECT"
check_command

./rep_delete_doc "$SESSION_FILE" "$DOCUMENT_NAME"
check_command


private_metadata=$(jq -r '.private_metadata' "$METADATA_FILE")
touch private_metadata.json

echo "$private_metadata" > private_metadata.json

echo "Decrypting file..."
./rep_decrypt_file "$ENCRYPTED_FILE" "./private_metadata.json"
check_command

cd ../role || {
    echo "Error: role directory not found."
    exit 1
}

echo "Testing role management with manager..."
./rep_add_role "$SESSION_FILE" "$TEST_ROLE"
check_command

./rep_add_permission "$SESSION_FILE" "$TEST_ROLE" "DOC_READ"
check_command
./rep_add_permission "$SESSION_FILE" "$TEST_ROLE" "DOC_ACL"
check_command

./rep_add_permission "$SESSION_FILE" "$TEST_ROLE" "$REGULAR_USER"
check_command

./rep_list_roles "$SESSION_FILE"
check_command

./rep_list_role_subjects "$SESSION_FILE" "$TEST_ROLE"
check_command

./rep_list_role_permissions "$SESSION_FILE" "$TEST_ROLE"
check_command

cd ../document || {
    echo "Error: document directory not found."
    exit 1
}
./rep_acl_doc "$SESSION_FILE" "$DOCUMENT_NAME" "+" "$TEST_ROLE" "DOC_READ"
check_command

docker-compose down
