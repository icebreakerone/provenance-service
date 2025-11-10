#!/bin/bash
# Script to verify a certificate and its signing

CERT_FILE="/Users/kipparker/Code/IceBreakerOne/provenance-service/scripts/Test-provenance-API (1).pem"
INTERMEDIATE_CA="/Users/kipparker/Code/IceBreakerOne/provenance-service/certs/intermediate.pem"
ROOT_CA="/Users/kipparker/Code/IceBreakerOne/provenance-service/certs/root-ca.pem"

echo "=== 1. Certificate Information ==="
openssl x509 -in "$CERT_FILE" -text -noout

echo ""
echo "=== 2. Certificate Validity Period ==="
openssl x509 -in "$CERT_FILE" -noout -dates

echo ""
echo "=== 3. Certificate Subject and Issuer ==="
openssl x509 -in "$CERT_FILE" -noout -subject -issuer

echo ""
echo "=== 4. Certificate Fingerprint ==="
openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256

echo ""
echo "=== 5. Certificate Public Key Info ==="
openssl x509 -in "$CERT_FILE" -noout -pubkey

echo ""
echo "=== 6. Verify Certificate Structure ==="
openssl x509 -in "$CERT_FILE" -noout -text 2>&1 | head -20

echo ""
echo "=== 7. Check Certificate Signature Algorithm ==="
openssl x509 -in "$CERT_FILE" -noout -text | grep -A 1 "Signature Algorithm"

echo ""
echo "=== 8. Verify Certificate Chain ==="
echo "Checking if certificate is signed by intermediate CA..."
if [ -f "$INTERMEDIATE_CA" ]; then
    openssl verify -CAfile "$INTERMEDIATE_CA" "$CERT_FILE"
else
    echo "⚠ Intermediate CA file not found: $INTERMEDIATE_CA"
fi

echo ""
echo "=== 9. Verify Full Chain (Certificate -> Intermediate -> Root) ==="
if [ -f "$INTERMEDIATE_CA" ] && [ -f "$ROOT_CA" ]; then
    # Create a combined CA file for verification
    COMBINED_CA=$(mktemp)
    cat "$INTERMEDIATE_CA" "$ROOT_CA" > "$COMBINED_CA"
    echo "Verifying full certificate chain..."
    openssl verify -CAfile "$COMBINED_CA" "$CERT_FILE"
    rm "$COMBINED_CA"
else
    echo "⚠ CA certificate files not found"
    echo "   Intermediate: $INTERMEDIATE_CA"
    echo "   Root: $ROOT_CA"
fi

echo ""
echo "=== 10. Check Certificate Chain Order ==="
echo "Certificate issuer:"
openssl x509 -in "$CERT_FILE" -noout -issuer
echo ""
if [ -f "$INTERMEDIATE_CA" ]; then
    echo "Intermediate CA subject:"
    openssl x509 -in "$INTERMEDIATE_CA" -noout -subject
    echo ""
    echo "Intermediate CA issuer:"
    openssl x509 -in "$INTERMEDIATE_CA" -noout -issuer
fi

