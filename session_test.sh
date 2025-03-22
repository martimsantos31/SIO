#!/bin/bash

ORG_NAME="an_org"
SUBJECT="gui"
SUBJECT_NAME="gui"
SUBJECT_EMAIL="gui@123.com"
PASSWORD="123"
CREDENTIALS_FILE="../credentials.json"
SESSION_FILE="../session/session.json"

cd src || {
    echo "Error: src directory not found."
    exit 1
}

docker-compose up -d


cd ./client
cd ./subject || {
    echo "Error: subject directory not found."
    exit 1
}
./rep_subject_credentials "$PASSWORD" "$CREDENTIALS_FILE"
cd ../organization || {
    echo "Error: organization directory not found."
    exit 1
}
./rep_create_org "$ORG_NAME" "$SUBJECT" "$SUBJECT_NAME" "$SUBJECT_EMAIL" "$CREDENTIALS_FILE"
cd ../session || {
    echo "Error: session directory not found."
    exit 1
}
./rep_create_session "$ORG_NAME" "$SUBJECT" "$PASSWORD" "$CREDENTIALS_FILE" "$SESSION_FILE"
