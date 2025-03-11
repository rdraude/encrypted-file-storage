#!/bin/bash

# Set up test environment
TEST_FILE="test_input.txt"
ENCRYPTED_DIR="./encrypted"
DECRYPTED_DIR="./decrypted"  # Ensure the correct decryption path
ENCRYPTED_FILE="$ENCRYPTED_DIR/$TEST_FILE"
DECRYPTED_FILE="$DECRYPTED_DIR/$TEST_FILE"
TEST_KEY="mysecretkey"

# Ensure directories exist
mkdir -p "$ENCRYPTED_DIR"
mkdir -p "$DECRYPTED_DIR"

# Create test file
echo "Hello, this is a test file!" > "$TEST_FILE"

# Run encryption
echo "Encrypting file..."
./encrypted-file-storage encrypt "$TEST_FILE" "$TEST_KEY"
if [ ! -f "$ENCRYPTED_FILE" ]; then
    echo "Encryption failed: File not found!"
    exit 1
fi
echo "File successfully encrypted."

# Run decryption
echo "Decrypting file..."
./encrypted-file-storage decrypt "$ENCRYPTED_FILE" "$TEST_KEY"
if [ ! -f "$DECRYPTED_FILE" ]; then
    echo "Decryption failed: File not found!"
    exit 1
fi
echo "File successfully decrypted."

# Compare original and decrypted files
if cmp -s "$TEST_FILE" "$DECRYPTED_FILE"; then
    echo "Test passed: Decrypted file matches original!"
    rm "$TEST_FILE" "$DECRYPTED_FILE" "$ENCRYPTED_FILE"  # Cleanup
    exit 0
else
    echo "Test failed: Decrypted file does NOT match original!"
    exit 1
fi
