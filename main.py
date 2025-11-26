from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from ib1.provenance.certificates import (  # type: ignore
    CertificatesProviderSelfContainedRecord,
)
from ib1.provenance import Record

from app import conf
from app.exceptions import ConfigurationError, FrameworkAuthError
from app.keystores import get_certificate, get_signer
from app.logger import get_logger
from app.models import EdpProvenanceRecordRequest, CapProvenanceRecordRequest
from app.provenance import create_edp_provenance_record, create_cap_provenance_record

logger = get_logger()

context = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not conf.ROOT_CA_CERTIFICATE:
        raise ValueError("ROOT_CA_CERTIFICATE is not set")
    if not conf.SIGNING_BUNDLE:
        raise ValueError("SIGNING_BUNDLE is not set")
    certificate_provider = CertificatesProviderSelfContainedRecord(
        get_certificate(conf.ROOT_CA_CERTIFICATE)
    )
    context["certificate_provider"] = certificate_provider
    signer = get_signer(certificate_provider)
    context["signer"] = signer
    yield
    certificate_provider = None


app = FastAPI(
    docs_url="/api-docs",
    title="IB1 Provenance Service API",
    lifespan=lifespan,
)


@app.get("/", response_model=dict)
def root():
    return {
        "urls": ["/datasources", "/datasources/{id}/{measure}"],
        "documentation": {
            "swagger_ui": "/docs",
            "redoc": "/redoc",
            "openapi_json": "/openapi.json",
            "changelog": "/changelog",
        },
    }


@app.post("/api/v1/sign/edp")
def sign_edp(request: EdpProvenanceRecordRequest):
    try:
        edp_record_encoded = create_edp_provenance_record(
            context["signer"],
            request.from_date,
            request.to_date,
            request.permission_granted,
            request.permission_expires,
            request.service_url,
            request.account,
            request.fapi_id,
            request.cap_member,
            request.origin_url,
            request.origin_license_url,
        )
        return edp_record_encoded
    except (
        Exception
    ) as exc:  # noqa: BLE001 - centralised error translation handles specifics
        _handle_endpoint_exception("create EDP provenance record", exc)


@app.post("/api/v1/sign/cap")
def sign_cap(request: CapProvenanceRecordRequest):
    try:
        cap_record_encoded = create_cap_provenance_record(
            context["signer"],
            context["certificate_provider"],
            request.edp_data_attachment,
            request.cap_member_id,
            request.bank_member_id,
            request.cap_account,
            request.cap_permission_granted,
            request.cap_permission_expires,
            request.grid_intensity_origin,
            request.grid_intensity_license,
            request.postcode,
            request.edp_service_url,
            request.edp_member_id,
            request.bank_service_url,
            request.from_date,
            request.to_date,
        )
        return cap_record_encoded
    except (
        Exception
    ) as exc:  # noqa: BLE001 - centralised error translation handles specifics
        _handle_endpoint_exception("create CAP provenance record", exc)


@app.post("/api/v1/decode")
def decode_provenance_record(record_encoded: dict):
    """Decode a provenance record from a dictionary."""
    record = Record(record_encoded["ib1:provenance"], record_encoded)
    record.verify(context["certificate_provider"])
    return record.decoded()


def _handle_endpoint_exception(action: str, exc: Exception):
    """
    Convert domain errors into HTTP errors while logging appropriately.
    """
    if isinstance(exc, (ValueError, FrameworkAuthError)):
        logger.warning("%s failed with client error: %s", action, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc) or f"Unable to {action} due to invalid input.",
        ) from exc

    if isinstance(exc, ConfigurationError):
        logger.error("%s failed due to service configuration: %s", action, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Signing service is not properly configured. Please try again later.",
        ) from exc

    logger.exception("Unexpected error while attempting to %s", action, exc_info=exc)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Unable to {action} at this time.",
    ) from exc
