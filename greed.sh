#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <folder_name> <contract_address>"
    exit 1
fi

# Activate the virtual environment (greed-venv)
source ~/greed/greed-venv/bin/activate

# Args
FOLDER_NAME=$1
ADDRESS=$2
TARGET_DIR="/tmp/$FOLDER_NAME"

# Check if Gigahorse analysis has already been performed
if [ -f "$TARGET_DIR/contract.tac" ]; then
    echo "Gigahorse analysis already exists at '$TARGET_DIR'. Skipping."
    exit 0
fi
# Create folder if it doesn't exist (-p)

mkdir -p "$TARGET_DIR"

# If the bytecode file doesn't already exist, download it

BYTECODE_FILE="$TARGET_DIR/contract.hex"

if [ -f "$BYTECODE_FILE" ]; then
    echo "Bytecode file already exists. Skipping download."
else
    python3 ./resources/download_bytecode.py "$ADDRESS" "$BYTECODE_FILE"

    # Check if the file was created successfully
    if [ ! -f "$BYTECODE_FILE" ]; then
        echo "Error: Bytecode file was not created. Aborting."
        exit 1
    fi
fi


cd "$TARGET_DIR" || { echo "Failed to enter directory $TARGET_DIR"; exit 1; }

chmod 777 contract.hex

# Run Gigahorse script

analyze_hex.sh --file contract.hex

# Run Greed

cd ..

greed "$TARGET_DIR" --debug

