#!/usr/bin/env bash
set -euo pipefail

# Run this from project root OR from dilithium/ref.
# It generates a fresh Dilithium3 Cloud signing key and writes a backend .env snippet.

if [ -x "./tools/dilithium3_tool" ]; then
  TOOL="./tools/dilithium3_tool"
elif [ -x "./tools/dilithium3_tool.exe" ]; then
  TOOL="./tools/dilithium3_tool.exe"
elif [ -x "./dilithium/ref/tools/dilithium3_tool" ]; then
  TOOL="./dilithium/ref/tools/dilithium3_tool"
elif [ -x "./dilithium/ref/tools/dilithium3_tool.exe" ]; then
  TOOL="./dilithium/ref/tools/dilithium3_tool.exe"
else
  echo "Cannot find dilithium3_tool. Build it first, then rerun this script." >&2
  exit 1
fi

KEY_FILE="cloud_dilithium3_keys.env"
BACKEND_ENV_FILE="cloud_dilithium3_backend.env"

"$TOOL" keygen > "$KEY_FILE"

PUBLIC_KEY_HEX=$(grep '^publicKeyHex=' "$KEY_FILE" | cut -d= -f2)
SECRET_KEY_HEX=$(grep '^secretKeyHex=' "$KEY_FILE" | cut -d= -f2)

if [ -z "$PUBLIC_KEY_HEX" ] || [ -z "$SECRET_KEY_HEX" ]; then
  echo "Key generation failed: missing publicKeyHex or secretKeyHex" >&2
  exit 1
fi

cat > "$BACKEND_ENV_FILE" <<ENVEOF
# Copy these lines to your backend .env
DILITHIUM3_TOOL_PATH=$TOOL
CLOUD_DILITHIUM_KEY_ID=cloud-dilithium3-key-v1
CLOUD_DILITHIUM_PUBLIC_KEY_HEX=$PUBLIC_KEY_HEX
CLOUD_DILITHIUM_SECRET_KEY_HEX=$SECRET_KEY_HEX
ENVEOF

chmod 600 "$KEY_FILE" "$BACKEND_ENV_FILE" 2>/dev/null || true

echo "Generated fresh Dilithium3 keys."
echo "Raw key file: $KEY_FILE"
echo "Backend .env snippet: $BACKEND_ENV_FILE"
echo ""
echo "IMPORTANT: Do not commit these files. Keep CLOUD_DILITHIUM_SECRET_KEY_HEX private."
echo "Public key length: ${#PUBLIC_KEY_HEX} hex chars"
echo "Secret key length: ${#SECRET_KEY_HEX} hex chars"
