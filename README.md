# Provenance Service

An API providing endpoints for provenance record creation and signing

## Start dev server

First create a .env file with the following entries:

```shell
# .env
ROOT_CA_CERTIFICATE=./certs/root-ca.pem
# SIGNING_KEY=./certs/vibt9775-key.pem
KMS_KEY_ID=xxxxxx-xxxxxx
SIGNING_BUNDLE=./certs/signing-issued-intermediate-bundle-kms.pem
SCHEME_URI=https://registry.core.sandbox.trust.ib1.org/scheme/perseus
AWS_DEFAULT_REGION=eu-west-2
AWS_ACCESS_KEY_ID=AKAKAKAKAKAKA
AWS_SECRET_ACCESS_KEY=ASJDKLASJD6789812394817
```

Start the dev server

```bash
uv sync
uv run fastapi dev main.py
```

Run the test client

```bash
uv run test_client.py
```

## Certificates required

Use your member account on directory to create a signing certificate and download the signing root and intermediate CA certificates. A signing bundle should be created from the leaf certificate and intermediate CA certificate.

## Env file

```
ROOT_CA_CERTIFICATE=./certs/root-ca.pem
SIGNING_KEY=./certs/my-key.pem
SIGNING_BUNDLE=./certs/signing-issued-intermediate-bundle.pem
SCHEME_URI=https://registry.core.sandbox.trust.ib1.org/scheme/perseus
```

Optional values to run the included dockerfile

```
AWS_DEFAULT_REGION=eu-west-2
AWS_ACCESS_KEY_ID=XXXXX
AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXX
```

## Docker

The included docker file is used in the example deployment. You can run it locally with:

```bash
docker run -v `pwd`/certs:/app/certs -p 8080:8080 --env-file=.env -it prod-build
```

## KMS Key Setup

### Creating a KMS Key for Signing

Create a new KMS key suitable for signing CSRs and provenance records (ECC P‑256 / ECDSA):

```bash
# Create the KMS key
aws kms create-key \
  --description "Provenance signing key (ECDSA P-256)" \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --origin AWS_KMS \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "Enable IAM User Permissions",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:root"
        },
        "Action": "kms:*",
        "Resource": "*"
      },
      {
        "Sid": "Allow signing operations",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:user/YOUR_USERNAME"
        },
        "Action": [
          "kms:Sign",
          "kms:Verify",
          "kms:DescribeKey",
          "kms:GetPublicKey"
        ],
        "Resource": "*"
      }
    ]
  }'
```

### Key Configuration Details

- **Key Usage**: `SIGN_VERIFY` - Enables cryptographic signing and verification operations
- **Key Spec**: `ECC_NIST_P256` - secp256r1 (P‑256) ECDSA key
- **Origin**: `AWS_KMS` - Key is generated and managed entirely within AWS KMS
- **Policy**: Custom policy allowing signing operations for your IAM user/role

### Alternative: Create Key with Alias

For easier management, create an alias for your key (ECC P‑256):

```bash
# First create the key (save the KeyId from the response)
# Create the ECC P-256 key
KEY_ID=$(aws kms create-key \
  --description "Provenance signing key (ECDSA P-256)" \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --origin AWS_KMS \
  --query 'KeyMetadata.KeyId' \
  --output text)

# Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/test-provenance-signing-key \
  --target-key-id $KEY_ID
```

### Required IAM Permissions

Ensure your IAM user/role has the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:Verify",
        "kms:DescribeKey",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

## Usage

### Signing CSRs with KMS (ECDSA P‑256)

Use the provided script to sign a CSR with your KMS key:

```bash
python scripts/sign-with-kms.py temp.csr your-kms-key-id us-east-1 final.csr
```

Or using the alias:

```bash
python scripts/sign-with-kms.py temp.csr alias/provenance-signing-key us-east-1 final.csr
```

Scripts to verify your keys:

```bash

cd scripts
./verify-certificate.sh
```

### KMS Signing Parameters

- Use `SigningAlgorithm=ECDSA_SHA_256` for ECC_NIST_P256 keys
- Use `MessageType=RAW` and pass the exact ASN.1 CertificationRequestInfo (CRI) DER bytes as the Message

### Key Features

- **Non-exportable**: Private keys never leave AWS KMS, ensuring maximum security
- **Audit Trail**: All signing operations are logged in AWS CloudTrail
- **Compliance**: Meets FIPS 140-2 Level 3 requirements for high-security environments
- **Multi-purpose**: Can be used for both CSR signing and permission record signing in the trust framework
