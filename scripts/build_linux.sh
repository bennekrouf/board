#!/bin/bash
set -e

# Define target
TARGET="x86_64-unknown-linux-musl"

echo "Checking for 'cross'..."
if ! command -v cross &> /dev/null; then
    echo "'cross' could not be found. Installing via cargo..."
    cargo install cross
fi

echo "Building for target: $TARGET ..."
cross build --release --target "$TARGET"

echo "Build complete."
OUTPUT_DIR="target/$TARGET/release/board"
DEST="board-linux-x86_64"

if [ -f "$OUTPUT_DIR" ]; then
    cp "$OUTPUT_DIR" "$DEST"
    echo "Binary copied to ./$DEST"
    echo "You can now copy '$DEST' to your Linux server."
else
    echo "Error: Output binary not found at $OUTPUT_DIR"
    exit 1
fi
