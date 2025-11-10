# Certificate Management Cheat Sheet

## Certificate Verification

### Verify certificate chain

```bash
openssl verify -CAfile root-ca.pem -untrusted intermediate.pem leaf-cert.pem
```

- Verifies a certificate against root CA with intermediate certificate

### Verify certificate bundle

```bash
openssl verify -CAfile root-ca.pem signing-bundle.pem
```

- Verifies a bundle containing multiple certificates

## Certificate Inspection

### View certificate details

```bash
openssl x509 -in certificate.pem -text -noout
```

- Shows full certificate details (subject, issuer, extensions, etc.)

### Check certificate public key

```bash
openssl x509 -in certificate.pem -pubkey -noout | openssl pkey -pubin -text -noout
```

- Extracts and displays the public key from a certificate

### Check certificate subject and issuer

```bash
openssl x509 -in certificate.pem -subject -issuer -noout
```

- Shows only the subject and issuer fields

## Certificate Bundle Management

### Count certificates in bundle

```bash
grep -c "BEGIN CERTIFICATE" signing-bundle.pem
```

- Counts how many certificates are in a bundle

### View all certificates in bundle

```bash
openssl crl2pkcs7 -nocrl -certfile signing-bundle.pem | openssl pkcs7 -print_certs -text -noout
```

- Shows all certificates in a bundle with full details

### View certificate subjects in bundle

```bash
openssl crl2pkcs7 -nocrl -certfile signing-bundle.pem | openssl pkcs7 -print_certs -noout | grep "Subject:"
```

- Shows only the subject lines for all certificates in bundle

### Extract leaf certificate from bundle

```bash
awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' bundle.pem | tail -n +$(grep -n "BEGIN CERTIFICATE" bundle.pem | tail -1 | cut -d: -f1) > leaf.crt
```

- Extracts the last (leaf) certificate from a bundle

## CSR Management

### View CSR details

```bash
openssl req -in csr.pem -text -noout
```

- Shows CSR details (subject, public key, extensions)

### Check CSR public key

```bash
openssl req -in csr.pem -pubkey -noout | openssl pkey -pubin -text -noout
```

- Extracts and displays the public key from a CSR

### Verify CSR signature

```bash
openssl req -in csr.pem -verify -noout
```

- Verifies that the CSR is properly signed

## Key Generation

### Generate ECDSA P-256 private key

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out key.pem
```

- Creates a new ECDSA P-256 private key

### Generate CSR from private key

```bash
openssl req -new -key key.pem -out csr.pem -subj "/C=GB/ST=State/O=Organization/CN=common-name"
```

- Creates a CSR using an existing private key

## AWS KMS Integration

### Get KMS public key

```bash
aws kms get-public-key --key-id <key-id> --region <region> --query 'PublicKey' --output text | base64 -d | openssl pkey -pubin -text -noout
```

- Retrieves and displays the public key from an AWS KMS key

### Compare certificate and KMS public keys

```bash
# Get certificate public key
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -text -noout

# Get KMS public key
aws kms get-public-key --key-id <key-id> --region <region> --query 'PublicKey' --output text | base64 -d | openssl pkey -pubin -text -noout
```

- Compare public keys to ensure they match

## Common Issues

### Certificate/Key Mismatch

- **Symptom**: `InvalidSignature` errors during verification
- **Cause**: Certificate public key doesn't match the signing key
- **Fix**: Ensure certificate was issued from CSR created with the same key

### Bundle Order Issues

- **Symptom**: Certificate chain verification fails
- **Cause**: Certificates in wrong order (leaf should be first, then intermediate)
- **Fix**: Reorder certificates in bundle file

### PEM Format Issues

- **Symptom**: Parsing errors with `asn1crypto` or similar tools
- **Cause**: File encoding issues or mixed DER/PEM formats
- **Fix**: Ensure consistent PEM format with proper line endings
