from functools import lru_cache
import os

import boto3  # type: ignore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from ib1.provenance.signing import SignerInMemory, SignerKMS  # type: ignore
from .exceptions import (
    KeyNotFoundError,
)

from app import conf

from app.logger import get_logger

logger = get_logger()


@lru_cache(maxsize=None)
def get_boto3_client(service_name):
    return boto3.client(service_name)


def get_signer(certificate_provider) -> "SignerInMemory | SignerKMS":
    """
    Construct and return a signer suitable for the environment.

    Strategy:
    1) If KMS is configured (env KMS_KEY_ID present), create a SignerKMS.
    2) Otherwise, attempt to load the private key from SSM using SIGNING_KEY as the parameter name.
    3) Fallback to loading the private key from a local file at SIGNING_KEY.

    Args:
        certificate_provider: Certificates provider for verification/embedding policy.

    Raises:
        KeyNotFoundError: If a local/SSM key is not found when required.

    Returns:
        SignerInMemory | SignerKMS: Configured signer instance.


    """
    # Load signer's certificate chain (used by both signer types)
    signer_chain_pem = get_certificate(conf.SIGNING_BUNDLE)  # type: ignore[arg-type]
    certificates = x509.load_pem_x509_certificates(signer_chain_pem)

    # 1) Prefer KMS when configured
    kms_key_id = os.environ.get("KMS_KEY_ID") or None  # explicit None if unset
    if kms_key_id:
        try:
            kms_client = get_boto3_client("kms")
            return SignerKMS(certificate_provider, certificates, kms_client, kms_key_id)
        except Exception as e:
            logger.warning(f"Falling back from KMS to local key due to error: {e}")

    try:
        with open(conf.SIGNING_KEY, "rb") as key_file:  # type: ignore[arg-type]
            key_pem = key_file.read()
    except FileNotFoundError:
        raise KeyNotFoundError(
            "Signing key not found in KMS or local file, check configuration."
        )

    private_key = serialization.load_pem_private_key(
        key_pem, password=None, backend=default_backend()
    )
    return SignerInMemory(certificate_provider, certificates, private_key)


def get_certificate(certificate_path: str) -> bytes:
    if certificate_path.startswith("s3://"):
        s3_client = get_boto3_client("s3")
        logger.info(f"Getting certificate from s3: {certificate_path}")
        bucket, key = certificate_path.split("s3://")[1].split("/", 1)
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        certificate = obj["Body"].read()

    else:
        with open(certificate_path, "rb") as cert_file:
            certificate = cert_file.read()
    return certificate
