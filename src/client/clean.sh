#!/bin/bash

EXPECTED_DIR="/src/client/"
CURRENT_DIR=$(pwd | sed "s|.*/src/client||")

if [ "$CURRENT_DIR" != "" ]; then
  echo "You are executing in an unexpected directory: $CURRENT_DIR"
  exit 1
fi

KEEP_FILES=(
  ".env"
  "clean.sh"
  "__init__.py"
  "__pycache__"
  "client.py"
  "rep_acl_doc"
  "rep_activate_subject"
  "rep_add_doc"
  "rep_add_permission"
  "rep_add_role"
  "rep_add_subject"
  "rep_assume_role"
  "rep_create_org"
  "rep_create_session"
  "rep_decrypt_file"
  "rep_delete_doc"
  "rep_drop_role"
  "rep_get_doc_file"
  "rep_get_doc_metadata"
  "rep_get_file"
  "rep_list_docs"
  "rep_list_orgs"
  "rep_list_permission_roles"
  "rep_list_role_permissions"
  "rep_list_role_subjects"
  "rep_list_roles"
  "rep_list_subject_roles"
  "rep_list_subjects"
  "rep_pub_key.pem"
  "rep_reactivate_role"
  "rep_remove_permission"
  "rep_subject_credentials"
  "rep_suspend_role"
  "rep_suspend_subject"
  "test_p1.sh"
  ".venv"
)

KEEP_PATTERN=$(printf "|%s" "${KEEP_FILES[@]}")
KEEP_PATTERN=${KEEP_PATTERN:1}

find . -type f | grep -Ev "${KEEP_PATTERN}" | while read -r file; do
  echo "Deleting $file"
  rm "$file"
done

find . -type d ! -path . | grep -Ev "${KEEP_PATTERN}" | while read -r dir; do
  echo "Deleting directory $dir"
  rm -r "$dir"
done
