import os
from dotenv import load_dotenv

load_dotenv()

ROOT_CA_CERTIFICATE = os.environ.get("ROOT_CA_CERTIFICATE")
SIGNING_KEY = os.environ.get("SIGNING_KEY")
SIGNING_BUNDLE = os.environ.get("SIGNING_BUNDLE")
SCHEME_URL = os.environ.get(
    "SCHEME_URI", "https://registry.core.sandbox.trust.ib1.org/scheme/perseus"
)
TRUST_FRAMEWORK_URL = os.environ.get(
    "TRUST_FRAMEWORK_URL", "https://registry.core.sandbox.trust.ib1.org/trust-framework"
)
