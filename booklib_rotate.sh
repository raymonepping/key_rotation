#!/bin/bash

# Exit if any command fails
set -e

# Run the secret rotation script
./secret_rotation.sh rotate \
  --mount kv --path booklib/api \
  --transit-key booklib-aes --cipher-field ciphertext \
  --show

# Capture the ciphertext from the rotated secret
CT=$(vault kv get -format=json kv/booklib/api | jq -r '.data.data.ciphertext')

# Decrypt the ciphertext to get the plaintext value
VAL=$(vault write -format=json transit/decrypt/booklib-aes ciphertext="$CT" \
      | jq -r '.data.plaintext' | base64 -d)

# Get the new version and update time
VER=$(vault kv get -format=json kv/booklib/api | jq -r '.data.metadata.version')
UPD=$(vault kv get -format=json kv/booklib/api | jq -r '.data.metadata.updated_time // .data.metadata.created_time')

# Write the new values to the environment file
cat > ../../key_rotation/rendered/booklib.env <<EOF
PASSWORD=${VAL}
VERSION=${VER}
UPDATED=${UPD}
EOF

echo "Secret rotation complete. The booklib.env file has been updated."