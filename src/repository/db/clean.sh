#!/bin/bash

EXPECTED_DIR="/src/repository/db"
CURRENT_DIR=$(pwd | sed "s|.*/src/repository/db||")

if [ "$CURRENT_DIR" != "" ]; then
  echo "You are executing in an unexpected directory: $CURRENT_DIR"
  exit 1
fi

rm "files.json"
rm "sessions.json"
rm "organizations.json"

touch "files.json"
touch "sessions.json"
touch "organizations.json"

echo "Cleaned up repository directory"
