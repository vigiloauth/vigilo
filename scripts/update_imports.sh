#!/bin/bash

# This script updates all Go import paths in the project to reflect a new major version.
# Specifically, it replaces occurrences of "github.com/vigiloauth/vigilo/{CURRENT_VERSION}" with
# "github.com/vigiloauth/vigilo/{NEW_VERSION}" in all .go files within the project.

CURRENT_VERSION=v2
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT="$SCRIPT_DIR/.."
IMPORT_PATH=github.com/vigiloauth/vigilo

while true; do
    read -p "Enter the new version (e.g., 4 for v4): " NEW_VERSION

    if [[ -z "$NEW_VERSION" ]]; then
        echo -e "Error: Version cannot be empty. Please try again.\n\n"
        continue
    fi

    if ! [[ "$NEW_VERSION" =~ ^[0-9]+$ ]]; then
        echo -e "Error: Version must be a number. Please try again.\n\n"
        continue
    fi

    NEW_VERSION="v$NEW_VERSION"
    break
done

# Navigate to the root of the project
cd "$PROJECT_ROOT" || exit 1

# Find all .go files and update imports
find "$PROJECT_ROOT" \
    -type f \
    -name "*.go" \
    -exec sed -i '' "s|$IMPORT_PATH/$CURRENT_VERSION|$IMPORT_PATH/$NEW_VERSION|g" {} +

echo "Import paths updated from $CURRENT_VERSION to $NEW_VERSION successfully."