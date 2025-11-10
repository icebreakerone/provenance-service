import datetime

from ib1.provenance import Record  # type: ignore
from ib1.provenance.signing import SignerInMemory  # type: ignore
from ib1.provenance.certificates import (  # type: ignore
    CertificatesProviderSelfContainedRecord,
)

from .logger import get_logger
from .conf import SCHEME_URL, TRUST_FRAMEWORK_URL

logging = get_logger()


def create_edp_provenance_record(
    signer: SignerInMemory,
    from_date: datetime.date,
    to_date: datetime.date,
    permission_granted: datetime.datetime,
    permission_expires: datetime.datetime,
    service_url: str,
    account: str,
    fapi_id: str,
    cap_member: str,
    origin_url: str,
    origin_license_url: str,
) -> dict:

    edp_record = Record(TRUST_FRAMEWORK_URL)
    # - Permission step to record consent by end user
    edp_permission_id = edp_record.add_step(
        {
            "type": "permission",
            "scheme": SCHEME_URL,
            "timestamp": f"{permission_granted.isoformat()[0:-7]}Z",
            "account": account,
            "allows": {
                "licences": [f"{SCHEME_URL}/licence/energy-consumption-data/2024-12-05"]
            },
            "expires": f"{permission_expires.isoformat()[0:-7]}Z",
        }
    )
    origin_id = edp_record.add_step(
        {
            "type": "origin",
            "scheme": SCHEME_URL,
            "sourceType": f"{SCHEME_URL}/source-type/Meter",
            "origin": origin_url,
            "originLicence": origin_license_url,
            "external": True,
            "permissions": [edp_permission_id],
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": f"{from_date.isoformat()}Z",
                    "to": f"{to_date.isoformat()}Z",
                }
            },
            "perseus:assurance": {
                "dataSource": f"{SCHEME_URL}/assurance/data-source/SmartMeter",
            },
        }
    )

    # - Transfer step to send it to the CAP
    edp_record.add_step(
        {
            "type": "transfer",
            "scheme": SCHEME_URL,
            "of": origin_id,
            "to": cap_member,
            "standard": f"{SCHEME_URL}/standard/energy-consumption-data/2024-12-05",
            "licence": f"{SCHEME_URL}/licence/energy-consumption-data/2024-12-05",
            "service": service_url,
            "path": "/readings",
            "parameters": {
                "measure": "import",
                "from": f"{from_date.isoformat()}Z",
                "to": f"{to_date.isoformat()}Z",
            },
            "permissions": [edp_permission_id],
            "transaction": fapi_id,
        }
    )

    # EDP signs the steps
    edp_record_signed = edp_record.sign(signer)
    edp_data_attachment = edp_record_signed.encoded()
    print("EDP data attachment type: ", type(edp_data_attachment))
    print("EDP data attachment: ", edp_data_attachment)
    return edp_data_attachment


def create_cap_provenance_record(
    signer: SignerInMemory,
    certificate_provider: CertificatesProviderSelfContainedRecord,
    edp_data_attachment: dict,
    cap_member_id: str,
    bank_member_id: str,
    cap_account: str,
    cap_permission_granted: datetime.datetime,
    cap_permission_expires: datetime.datetime,
    grid_intensity_origin: str,
    grid_intensity_license: str,
    postcode: str,
    edp_service_url: str,
    edp_member_id: str,
    bank_service_url: str,
    from_date: datetime.date,
    to_date: datetime.date,
) -> dict:
    """
    Create a CAP provenance record that processes EDP data and transfers to bank.

    Args:
        signer: KMS signer for the CAP
        certificate_provider: Certificate provider for verification
        edp_data_attachment: Encoded EDP provenance record
        cap_member_id: CAP member identifier
        bank_member_id: Bank member identifier
        cap_account: CAP's account identifier
        cap_permission_granted: When CAP permission was granted
        cap_permission_expires: When CAP permission expires
        grid_intensity_origin: Grid intensity data origin URL
        grid_intensity_license: Grid intensity data license URL
        postcode: Postcode for grid intensity data
        edp_service_url: EDP service URL for meter readings
        edp_member_id: EDP member identifier
        bank_service_url: Bank service URL for emissions reporting
        from_date: Start date for data period
        to_date: End date for data period

    Returns:
        Encoded CAP provenance record
    """

    # Create CAP record from EDP data
    print(
        "CAP: Creating record with EDP data attachment type:", type(edp_data_attachment)
    )
    print(
        "CAP: EDP data attachment keys:",
        (
            list(edp_data_attachment.keys())
            if isinstance(edp_data_attachment, dict)
            else "Not a dict"
        ),
    )
    cap_record = Record(TRUST_FRAMEWORK_URL, edp_data_attachment)

    # Debug: Print all steps in the EDP record immediately after creation
    steps_info = []
    for i, step in enumerate(cap_record._record["steps"]):
        step_info = f"Step {i}: {step}"
        steps_info.append(step_info)
        print(step_info)

    # Also log to the logger for visibility
    logging.info(f"CAP: EDP record has {len(cap_record._record['steps'])} steps")
    logging.info(f"CAP: Steps: {steps_info}")

    # Verify the signatures on the EDP record
    cap_record.verify(certificate_provider)
    # Find the transfer step from EDP
    search_criteria = {
        "type": "transfer",
        "scheme": SCHEME_URL,
        "to": cap_member_id,
        "standard": f"{SCHEME_URL}/standard/energy-consumption-data/2024-12-05",
        "licence": f"{SCHEME_URL}/licence/energy-consumption-data/2024-12-05",
        "service": edp_service_url,
        "path": "/readings",
        "parameters": {
            "measure": "import",
            "from": f"{from_date.isoformat()}Z",
            "to": f"{to_date.isoformat()}Z",
        },
        "_signature": {
            "signed": {
                "member": edp_member_id,
                "roles": [f"{SCHEME_URL}/role/carbon-accounting-provider"],
            }
        },
    }

    logging.info(f"CAP: Looking for transfer step with criteria: {search_criteria}")
    transfer_from_edp_step = cap_record.find_step(search_criteria)

    # Add receipt step
    cap_receipt_id = cap_record.add_step(
        {"type": "receipt", "transfer": transfer_from_edp_step["id"]}
    )

    # Add CAP permission step
    cap_permission_id = cap_record.add_step(
        {
            "type": "permission",
            "scheme": SCHEME_URL,
            "timestamp": f"{cap_permission_granted.isoformat()[0:-7]}Z",
            "account": cap_account,
            "allows": {
                "licenses": [f"{SCHEME_URL}/license/emissions-report/2024-12-05"],
                "processes": [
                    f"{SCHEME_URL}/process/emissions-calculations/2024-12-05"
                ],
            },
            "expires": f"{cap_permission_expires.isoformat()[0:-7]}Z",
        }
    )

    # Add grid intensity origin step
    cap_intensity_origin_id = cap_record.add_step(
        {
            "type": "origin",
            "scheme": SCHEME_URL,
            "sourceType": f"{SCHEME_URL}/source-type/GridCarbonIntensity",
            "origin": grid_intensity_origin,
            "originLicense": grid_intensity_license,
            "external": True,
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": f"{from_date.isoformat()}Z",
                    "to": f"{to_date.isoformat()}Z",
                },
                "postcode": postcode,
            },
            "perseus:assurance": {
                "missingData": f"{SCHEME_URL}/assurance/missing-data/Complete"
            },
        }
    )

    # Add processing step
    cap_processing_id = cap_record.add_step(
        {
            "type": "process",
            "scheme": SCHEME_URL,
            "inputs": [cap_receipt_id, cap_intensity_origin_id],
            "process": f"{SCHEME_URL}/process/emissions-calculations/2024-12-05",
            "permissions": [cap_permission_id],
            "perseus:assurance": {
                "missingData": f"{SCHEME_URL}/assurance/missing-data/Substituted"
            },
        }
    )

    # Add transfer step to bank
    cap_record.add_step(
        {
            "type": "transfer",
            "scheme": SCHEME_URL,
            "of": cap_processing_id,
            "to": bank_member_id,
            "standard": f"{SCHEME_URL}/standard/emissions-report/2024-12-05",
            "licence": f"{SCHEME_URL}/licence/emissions-report/2024-12-05",
            "service": bank_service_url,
            "path": "/emissions",
            "parameters": {
                "from": f"{from_date.isoformat()}Z",
                "to": f"{to_date.isoformat()}Z",
            },
            "permissions": [cap_permission_id],
        }
    )

    # CAP signs the steps
    cap_record_signed = cap_record.sign(signer)
    cap_data_attachment = cap_record_signed.encoded()
    return cap_data_attachment
