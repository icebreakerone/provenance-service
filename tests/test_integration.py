"""End-to-end tests against the real ib1-provenance library.

test_main.py replaces the library with stubs, so it would not notice a change in
the library's behaviour. These tests sign and verify real records, using an
in-memory PKI shaped like the Directory's signing certificates (tests/pki.py,
copied from the ib1-provenance test suite).
"""

import base64
import datetime
import json

import pytest
from fastapi.testclient import TestClient
from ib1.provenance import Record
from ib1.provenance.certificates import CertificatesProviderSelfContainedRecord

import main
from app.conf import SCHEME_URL, TRUST_FRAMEWORK_URL
from app.provenance import (
    _iso_utc,
    create_cap_provenance_record,
    create_edp_provenance_record,
)
from pki import PKI

EDP_ROLE = f"{SCHEME_URL}/role/energy-data-provider"
CAP_ROLE = f"{SCHEME_URL}/role/carbon-accounting-provider"


@pytest.fixture(scope="module")
def pki():
    return PKI()


@pytest.fixture(scope="module")
def provider(pki):
    return CertificatesProviderSelfContainedRecord(pki.root_pem)


@pytest.fixture(scope="module")
def edp(pki):
    return pki.member("Smart Meter Co", 2876152, 38936455, [EDP_ROLE], 123456)


@pytest.fixture(scope="module")
def cap(pki):
    return pki.member("Carbon Accounting Co", 81524, 26241, [CAP_ROLE], 98765)


FROM = datetime.datetime(2024, 9, 1, tzinfo=datetime.timezone.utc)
TO = datetime.datetime(2024, 9, 2, tzinfo=datetime.timezone.utc)


def _edp_record(edp, provider, cap, granted, expires):
    return create_edp_provenance_record(
        edp.signer(provider),
        FROM,
        TO,
        granted,
        expires,
        "https://edp.example.com",
        "edp-account",
        "fapi-123",
        cap.member,
        "https://www.smartdcc.co.uk/",
        "https://smartenergycodecompany.co.uk/the-smart-energy-code-2/",
    )


@pytest.mark.parametrize(
    "value, expected",
    [
        # Values from provenance-service#2, which isoformat()[0:-7] mangled
        ("2024-09-16T15:32:56Z", "2024-09-16T15:32:56Z"),
        ("2024-09-16T15:32:56", "2024-09-16T15:32:56Z"),
        ("2024-09-16T15:32:56.123456Z", "2024-09-16T15:32:56Z"),
        ("2024-09-16T15:32:56.123456", "2024-09-16T15:32:56Z"),
        ("2024-09-16T16:32:56+01:00", "2024-09-16T15:32:56Z"),
    ],
)
def test_iso_utc(value, expected):
    assert _iso_utc(datetime.datetime.fromisoformat(value)) == expected


@pytest.mark.parametrize(
    "granted, expires",
    [
        ("2024-09-16T15:32:56Z", "2025-09-16T15:32:56Z"),
        ("2024-09-16T15:32:56", "2025-09-16T15:32:56"),
        ("2024-09-16T15:32:56.123456+01:00", "2025-09-16T15:32:56.5+01:00"),
    ],
)
def test_edp_then_cap_record_signs_verifies_and_validates(
    edp, cap, provider, granted, expires
):
    granted = datetime.datetime.fromisoformat(granted)
    expires = datetime.datetime.fromisoformat(expires)

    edp_encoded = _edp_record(edp, provider, cap, granted, expires)

    edp_loaded = Record(TRUST_FRAMEWORK_URL, edp_encoded)
    edp_loaded.verify(provider)
    assert edp_loaded.validate() == []

    cap_encoded = create_cap_provenance_record(
        cap.signer(provider),
        provider,
        edp_encoded,
        cap.member,
        "https://directory.core.trust.ib1.org/member/bank",
        "cap-account",
        granted,
        expires,
        "https://api.carbonintensity.org.uk/",
        "https://creativecommons.org/licenses/by/4.0/",
        "AL10",
        "https://edp.example.com",
        edp.member,
        "https://bank.example.com",
        FROM,
        TO,
    )

    cap_loaded = Record(TRUST_FRAMEWORK_URL, cap_encoded)
    cap_loaded.verify(provider)
    assert cap_loaded.validate() == []

    steps = cap_loaded.decoded()
    assert [s["type"] for s in steps] == [
        "permission",
        "origin",
        "transfer",
        "receipt",
        "permission",
        "origin",
        "process",
        "transfer",
    ]
    for step in steps:
        if step["type"] == "permission":
            assert step["timestamp"] == _iso_utc(granted)
            assert step["expires"] == _iso_utc(expires)
    signers = {s["_signature"]["signed"]["member"] for s in steps}
    assert signers == {edp.member, cap.member}


def test_cap_rejects_edp_record_from_wrong_member(edp, cap, provider):
    granted = datetime.datetime(2024, 9, 16, tzinfo=datetime.timezone.utc)
    edp_encoded = _edp_record(
        edp, provider, cap, granted, granted + datetime.timedelta(days=365)
    )
    with pytest.raises(Exception):
        create_cap_provenance_record(
            cap.signer(provider),
            provider,
            edp_encoded,
            cap.member,
            "bank",
            "cap-account",
            granted,
            granted + datetime.timedelta(days=365),
            "https://api.carbonintensity.org.uk/",
            "https://creativecommons.org/licenses/by/4.0/",
            "AL10",
            "https://edp.example.com",
            "https://directory.core.trust.ib1.org/member/someone-else",
            "https://bank.example.com",
            FROM,
            TO,
        )


@pytest.fixture
def api(monkeypatch, pki, provider, edp):
    """The real app, with a signer for a member holding the EDP role."""
    main.context.clear()
    monkeypatch.setattr(main.conf, "ROOT_CA_CERTIFICATE", "unused")
    monkeypatch.setattr(main.conf, "SIGNING_BUNDLE", "unused")
    monkeypatch.setattr(main, "get_certificate", lambda path: pki.root_pem)
    monkeypatch.setattr(main, "get_signer", lambda p: edp.signer(p))
    with TestClient(main.app) as client:
        yield client
    main.context.clear()


def test_api_sign_edp_then_cap_then_decode(api, edp):
    edp_response = api.post(
        "/api/v1/sign/edp",
        json={
            "from_date": "2024-09-01T00:00:00Z",
            "to_date": "2024-09-02T00:00:00Z",
            "permission_granted": "2024-09-16T15:32:56Z",
            "permission_expires": "2025-09-16T15:32:56Z",
            "service_url": "https://edp.example.com",
            "account": "edp-account",
            "fapi_id": "fapi-123",
            "cap_member": edp.member,
            "origin_url": "https://www.smartdcc.co.uk/",
            "origin_license_url": "https://example.com/licence",
        },
    )
    assert edp_response.status_code == 200, edp_response.text
    edp_encoded = edp_response.json()

    cap_response = api.post(
        "/api/v1/sign/cap",
        json={
            "edp_data_attachment": edp_encoded,
            "cap_member_id": edp.member,
            "bank_member_id": "bank",
            "cap_account": "cap-account",
            "cap_permission_granted": "2024-09-16T15:32:56Z",
            "cap_permission_expires": "2025-09-16T15:32:56Z",
            "grid_intensity_origin": "https://api.carbonintensity.org.uk/",
            "grid_intensity_license": "https://example.com/licence",
            "postcode": "AL10",
            "edp_service_url": "https://edp.example.com",
            "edp_member_id": edp.member,
            "bank_service_url": "https://bank.example.com",
            "from_date": "2024-09-01T00:00:00Z",
            "to_date": "2024-09-02T00:00:00Z",
        },
    )
    assert cap_response.status_code == 200, cap_response.text

    decode_response = api.post("/api/v1/decode", json=cap_response.json())
    assert decode_response.status_code == 200, decode_response.text
    steps = decode_response.json()
    assert len(steps) == 8
    assert steps[0]["timestamp"] == "2024-09-16T15:32:56Z"


def test_api_decode_rejects_tampered_record(api, edp):
    response = api.post(
        "/api/v1/sign/edp",
        json={
            "from_date": "2024-09-01T00:00:00Z",
            "to_date": "2024-09-02T00:00:00Z",
            "permission_granted": "2024-09-16T15:32:56Z",
            "permission_expires": "2025-09-16T15:32:56Z",
            "service_url": "https://edp.example.com",
            "account": "edp-account",
            "fapi_id": "fapi-123",
            "cap_member": edp.member,
            "origin_url": "https://www.smartdcc.co.uk/",
            "origin_license_url": "https://example.com/licence",
        },
    )
    record = response.json()

    wrong_framework = dict(record, **{"ib1:provenance": TRUST_FRAMEWORK_URL + "/x"})
    assert api.post("/api/v1/decode", json=wrong_framework).status_code == 400

    # Change the account in the signed permission step
    steps = list(record["steps"])
    step = json.loads(base64.urlsafe_b64decode(steps[0]))
    step["account"] = "someone-else"
    steps[0] = base64.urlsafe_b64encode(json.dumps(step).encode()).decode()
    tampered = api.post("/api/v1/decode", json=dict(record, steps=steps))
    assert tampered.status_code == 400, tampered.text

    missing = api.post("/api/v1/decode", json={"steps": []})
    assert missing.status_code == 400
