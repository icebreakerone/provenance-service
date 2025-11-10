import main
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    main.context.clear()

    monkeypatch.setattr(main.conf, "ROOT_CA_CERTIFICATE", "/tmp/root-ca.pem")
    monkeypatch.setattr(main.conf, "SIGNING_BUNDLE", "/tmp/signing-bundle.pfx")

    class DummyCertificateProvider:
        def __init__(self, certificate):
            self.certificate = certificate

    def fake_get_certificate(path):
        return f"certificate:{path}"

    def fake_get_signer(provider):
        return f"signer-for:{provider.certificate}"

    monkeypatch.setattr(
        main, "CertificatesProviderSelfContainedRecord", DummyCertificateProvider
    )
    monkeypatch.setattr(main, "get_certificate", fake_get_certificate)
    monkeypatch.setattr(main, "get_signer", fake_get_signer)

    with TestClient(main.app) as test_client:
        yield test_client

    main.context.clear()


def test_root_endpoint_returns_expected_structure(client):
    response = client.get("/")
    assert response.status_code == 200

    payload = response.json()
    assert payload["urls"] == ["/datasources", "/datasources/{id}/{measure}"]
    assert payload["documentation"]["swagger_ui"] == "/docs"
    assert "signer" in main.context
    assert "certificate_provider" in main.context


def test_sign_edp_returns_encoded_record(client, monkeypatch):
    captured = {}

    def fake_create_edp_provenance_record(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"record": "encoded-edp"}

    monkeypatch.setattr(
        main, "create_edp_provenance_record", fake_create_edp_provenance_record
    )

    response = client.post(
        "/api/v1/sign/edp",
        json={
            "from_date": "2024-01-01T00:00:00Z",
            "to_date": "2024-01-02T00:00:00Z",
            "permission_granted": "2024-01-01T00:00:00Z",
            "permission_expires": "2024-02-01T00:00:00Z",
            "service_url": "https://example.com/service",
            "account": "acc-123",
            "fapi_id": "fapi-456",
            "cap_member": "cap-member",
            "origin_url": "https://example.com/origin",
            "origin_license_url": "https://example.com/license",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"record": "encoded-edp"}

    signer = captured["args"][0]
    assert signer == main.context["signer"]


def test_sign_cap_returns_encoded_record(client, monkeypatch):
    captured = {}

    def fake_create_cap_provenance_record(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"record": "encoded-cap"}

    monkeypatch.setattr(
        main, "create_cap_provenance_record", fake_create_cap_provenance_record
    )

    response = client.post(
        "/api/v1/sign/cap",
        json={
            "edp_data_attachment": {"record": "encoded-edp"},
            "cap_member_id": "cap-member",
            "bank_member_id": "bank-member",
            "cap_account": "cap-account",
            "cap_permission_granted": "2024-01-01T00:00:00Z",
            "cap_permission_expires": "2024-02-01T00:00:00Z",
            "grid_intensity_origin": "https://example.com/grid-origin",
            "grid_intensity_license": "https://example.com/grid-license",
            "postcode": "AB12CD",
            "edp_service_url": "https://example.com/edp",
            "edp_member_id": "edp-member",
            "bank_service_url": "https://example.com/bank",
            "from_date": "2024-01-01T00:00:00Z",
            "to_date": "2024-01-02T00:00:00Z",
        },
    )

    assert response.status_code == 200
    assert response.json() == {"record": "encoded-cap"}

    signer, certificate_provider = captured["args"][0], captured["args"][1]
    assert signer == main.context["signer"]
    assert certificate_provider == main.context["certificate_provider"]


def test_sign_cap_returns_400_on_expected_error(client, monkeypatch):
    def fake_create_cap_provenance_record(*args, **kwargs):
        raise ValueError("Cap creation failed")

    monkeypatch.setattr(
        main, "create_cap_provenance_record", fake_create_cap_provenance_record
    )

    response = client.post(
        "/api/v1/sign/cap",
        json={
            "edp_data_attachment": {"record": "encoded-edp"},
            "cap_member_id": "cap-member",
            "bank_member_id": "bank-member",
            "cap_account": "cap-account",
            "cap_permission_granted": "2024-01-01T00:00:00Z",
            "cap_permission_expires": "2024-02-01T00:00:00Z",
            "grid_intensity_origin": "https://example.com/grid-origin",
            "grid_intensity_license": "https://example.com/grid-license",
            "postcode": "AB12CD",
            "edp_service_url": "https://example.com/edp",
            "edp_member_id": "edp-member",
            "bank_service_url": "https://example.com/bank",
            "from_date": "2024-01-01T00:00:00Z",
            "to_date": "2024-01-02T00:00:00Z",
        },
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Cap creation failed"}


def test_sign_cap_returns_500_on_unexpected_error(client, monkeypatch):
    def fake_create_cap_provenance_record(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        main, "create_cap_provenance_record", fake_create_cap_provenance_record
    )

    response = client.post(
        "/api/v1/sign/cap",
        json={
            "edp_data_attachment": {"record": "encoded-edp"},
            "cap_member_id": "cap-member",
            "bank_member_id": "bank-member",
            "cap_account": "cap-account",
            "cap_permission_granted": "2024-01-01T00:00:00Z",
            "cap_permission_expires": "2024-02-01T00:00:00Z",
            "grid_intensity_origin": "https://example.com/grid-origin",
            "grid_intensity_license": "https://example.com/grid-license",
            "postcode": "AB12CD",
            "edp_service_url": "https://example.com/edp",
            "edp_member_id": "edp-member",
            "bank_service_url": "https://example.com/bank",
            "from_date": "2024-01-01T00:00:00Z",
            "to_date": "2024-01-02T00:00:00Z",
        },
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Unable to create CAP provenance record at this time."
    }


def test_sign_edp_returns_400_on_expected_error(client, monkeypatch):
    def fake_create_edp_provenance_record(*args, **kwargs):
        raise ValueError("invalid request")

    monkeypatch.setattr(
        main, "create_edp_provenance_record", fake_create_edp_provenance_record
    )

    response = client.post(
        "/api/v1/sign/edp",
        json={
            "from_date": "2024-01-01T00:00:00Z",
            "to_date": "2024-01-02T00:00:00Z",
            "permission_granted": "2024-01-01T00:00:00Z",
            "permission_expires": "2024-02-01T00:00:00Z",
            "service_url": "https://example.com/service",
            "account": "acc-123",
            "fapi_id": "fapi-456",
            "cap_member": "cap-member",
            "origin_url": "https://example.com/origin",
            "origin_license_url": "https://example.com/license",
        },
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid request"}
