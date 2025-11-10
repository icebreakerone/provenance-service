#!/usr/bin/env python3
"""
Script to verify a certificate and check its properties
"""

import argparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import sys


def verify_certificate(cert_path, ca_cert_path=None):
    """Verify certificate and display detailed information"""
    
    # Load certificate
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    
    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except Exception as e:
        print(f"Error loading certificate: {e}")
        return False
    
    print("=" * 70)
    print("CERTIFICATE VERIFICATION REPORT")
    print("=" * 70)
    
    # Basic information
    print(f"\n✓ Certificate loaded successfully")
    print(f"  File: {cert_path}")
    
    # Subject and Issuer
    print(f"\n📋 Subject: {cert.subject.rfc4514_string()}")
    print(f"📋 Issuer: {cert.issuer.rfc4514_string()}")
    
    # Validity period
    print(f"\n📅 Validity Period:")
    not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
    print(f"   Not Before: {not_before}")
    print(f"   Not After: {not_after}")
    
    now = datetime.now(not_before.tzinfo) if hasattr(not_before, 'tzinfo') and not_before.tzinfo else datetime.now()
    
    if not_before <= now <= not_after:
        print(f"   ✓ Certificate is currently valid")
    else:
        if now < not_before:
            print(f"   ⚠ Certificate is not yet valid")
        else:
            print(f"   ✗ Certificate has expired")
    
    # Serial number
    print(f"\n🔢 Serial Number: {cert.serial_number}")
    
    # Signature algorithm
    sig_alg_name = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
    print(f"\n🔐 Signature Algorithm: {sig_alg_name}")
    
    # Public key information
    public_key = cert.public_key()
    print(f"\n🔑 Public Key:")
    print(f"   Type: {type(public_key).__name__}")
    
    if hasattr(public_key, 'key_size'):
        print(f"   Key Size: {public_key.key_size} bits")
    
    # Fingerprints
    print(f"\n🔍 Fingerprints:")
    print(f"   SHA256: {cert.fingerprint(hashes.SHA256()).hex()}")
    print(f"   SHA1: {cert.fingerprint(hashes.SHA1()).hex()}")
    
    # Extensions
    print(f"\n📝 Extensions:")
    try:
        for ext in cert.extensions:
            print(f"   - {ext.oid._name}: {ext.value}")
    except Exception as e:
        print(f"   (Error reading extensions: {e})")
    
    # Verify signature (if CA cert provided)
    if ca_cert_path:
        print(f"\n🔗 Verifying Certificate Chain:")
        try:
            with open(ca_cert_path, 'rb') as f:
                ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
            
            # Get CA public key
            ca_public_key = ca_cert.public_key()
            
            # Verify signature
            try:
                sig_hash_alg = cert.signature_hash_algorithm
                
                # Determine the signature algorithm based on key type
                if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                    signature_algorithm = ec.ECDSA(sig_hash_alg)
                    ca_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        signature_algorithm,
                    )
                elif isinstance(ca_public_key, rsa.RSAPublicKey):
                    signature_algorithm = padding.PKCS1v15()
                    hasher = hashes.Hash(sig_hash_alg, default_backend())
                    hasher.update(cert.tbs_certificate_bytes)
                    digest = hasher.finalize()
                    ca_public_key.verify(
                        cert.signature,
                        digest,
                        signature_algorithm,
                    )
                else:
                    raise ValueError(f"Unsupported public key type: {type(ca_public_key)}")
                
                print(f"   ✓ Certificate signature is valid (signed by CA)")
            except Exception as e:
                print(f"   ✗ Certificate signature verification failed: {e}")
                return False
                
        except Exception as e:
            print(f"   ⚠ Could not verify against CA: {e}")
    else:
        print(f"\n⚠ No CA certificate provided - skipping chain verification")
        print(f"   To verify against CA, use: --ca-cert <path-to-ca-cert.pem>")
    
    print("\n" + "=" * 70)
    return True


def verify_certificate_chain(cert_path, intermediate_ca_path, root_ca_path):
    """Verify the full certificate chain"""
    print("\n" + "=" * 70)
    print("CERTIFICATE CHAIN VERIFICATION")
    print("=" * 70)
    
    try:
        # Load certificate
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Load intermediate CA
        with open(intermediate_ca_path, 'rb') as f:
            intermediate_data = f.read()
        intermediate_ca = x509.load_pem_x509_certificate(intermediate_data, default_backend())
        
        # Load root CA
        with open(root_ca_path, 'rb') as f:
            root_data = f.read()
        root_ca = x509.load_pem_x509_certificate(root_data, default_backend())
        
        # Verify certificate is signed by intermediate CA
        print("\n🔗 Step 1: Verifying certificate is signed by intermediate CA...")
        intermediate_public_key = intermediate_ca.public_key()
        try:
            # Get the signature algorithm from the certificate
            sig_hash_alg = cert.signature_hash_algorithm
            
            # Determine the signature algorithm based on key type
            if isinstance(intermediate_public_key, ec.EllipticCurvePublicKey):
                # ECDSA signature
                signature_algorithm = ec.ECDSA(sig_hash_alg)
            elif isinstance(intermediate_public_key, rsa.RSAPublicKey):
                # RSA signature with PKCS1v15 padding
                signature_algorithm = padding.PKCS1v15()
            else:
                raise ValueError(f"Unsupported public key type: {type(intermediate_public_key)}")
            
            # Verify the signature
            if isinstance(intermediate_public_key, ec.EllipticCurvePublicKey):
                intermediate_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    signature_algorithm,
                )
            else:
                # For RSA, we need to hash first
                hasher = hashes.Hash(sig_hash_alg, default_backend())
                hasher.update(cert.tbs_certificate_bytes)
                digest = hasher.finalize()
                intermediate_public_key.verify(
                    cert.signature,
                    digest,
                    signature_algorithm,
                )
            print("   ✓ Certificate signature is valid (signed by intermediate CA)")
        except Exception as e:
            print(f"   ✗ Certificate signature verification failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Verify intermediate CA is signed by root CA
        print("\n🔗 Step 2: Verifying intermediate CA is signed by root CA...")
        root_public_key = root_ca.public_key()
        try:
            # Get the signature algorithm from the intermediate CA
            intermediate_sig_hash_alg = intermediate_ca.signature_hash_algorithm
            
            # Determine the signature algorithm based on key type
            if isinstance(root_public_key, ec.EllipticCurvePublicKey):
                # ECDSA signature
                signature_algorithm = ec.ECDSA(intermediate_sig_hash_alg)
            elif isinstance(root_public_key, rsa.RSAPublicKey):
                # RSA signature with PKCS1v15 padding
                signature_algorithm = padding.PKCS1v15()
            else:
                raise ValueError(f"Unsupported public key type: {type(root_public_key)}")
            
            # Verify the signature
            if isinstance(root_public_key, ec.EllipticCurvePublicKey):
                root_public_key.verify(
                    intermediate_ca.signature,
                    intermediate_ca.tbs_certificate_bytes,
                    signature_algorithm,
                )
            else:
                # For RSA, we need to hash first
                hasher = hashes.Hash(intermediate_sig_hash_alg, default_backend())
                hasher.update(intermediate_ca.tbs_certificate_bytes)
                digest = hasher.finalize()
                root_public_key.verify(
                    intermediate_ca.signature,
                    digest,
                    signature_algorithm,
                )
            print("   ✓ Intermediate CA signature is valid (signed by root CA)")
        except Exception as e:
            print(f"   ✗ Intermediate CA signature verification failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Check issuer/subject chain
        print("\n🔗 Step 3: Verifying issuer/subject chain...")
        cert_issuer = cert.issuer.rfc4514_string()
        intermediate_subject = intermediate_ca.subject.rfc4514_string()
        
        if cert_issuer == intermediate_subject:
            print(f"   ✓ Certificate issuer matches intermediate CA subject")
        else:
            print(f"   ⚠ Certificate issuer: {cert_issuer}")
            print(f"   ⚠ Intermediate CA subject: {intermediate_subject}")
        
        intermediate_issuer = intermediate_ca.issuer.rfc4514_string()
        root_subject = root_ca.subject.rfc4514_string()
        
        if intermediate_issuer == root_subject:
            print(f"   ✓ Intermediate CA issuer matches root CA subject")
        else:
            print(f"   ⚠ Intermediate CA issuer: {intermediate_issuer}")
            print(f"   ⚠ Root CA subject: {root_subject}")
        
        print("\n" + "=" * 70)
        print("✓ Full certificate chain verification successful!")
        print("=" * 70)
        return True
        
    except FileNotFoundError as e:
        print(f"✗ Error: File not found - {e}")
        return False
    except Exception as e:
        print(f"✗ Error during chain verification: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify a certificate and display detailed information"
    )
    parser.add_argument(
        "cert",
        help="Path to the certificate file to verify"
    )
    parser.add_argument(
        "--ca-cert",
        help="Path to the CA certificate file for chain verification"
    )
    parser.add_argument(
        "--intermediate-ca",
        help="Path to the intermediate CA certificate file"
    )
    parser.add_argument(
        "--root-ca",
        help="Path to the root CA certificate file"
    )
    parser.add_argument(
        "--full-chain",
        action="store_true",
        help="Verify full certificate chain (requires --intermediate-ca and --root-ca)"
    )
    
    args = parser.parse_args()
    
    success = verify_certificate(args.cert, args.ca_cert)
    
    if args.full_chain:
        if args.intermediate_ca and args.root_ca:
            chain_success = verify_certificate_chain(args.cert, args.intermediate_ca, args.root_ca)
            success = success and chain_success
        else:
            print("\n⚠ --full-chain requires --intermediate-ca and --root-ca")
            success = False
    
    sys.exit(0 if success else 1)

