#!/usr/bin/env python3
"""
Simple test client for the provenance service endpoints.
"""

from pydantic.config import JsonDict
import requests
import json
import base64
from datetime import datetime, timedelta

# Configuration
BASE_URL = "http://localhost:8000"  # Adjust if running on different host/port
EDP_ENDPOINT = "/api/v1/sign/edp"
CAP_ENDPOINT = "/api/v1/sign/cap"


def create_edp_test_request():
    """Create a valid EDP test request payload."""
    # Use fixed timestamps for consistency between EDP and CAP requests
    from_date = datetime(2025, 9, 20, 10, 0, 0)
    to_date = datetime(2025, 10, 19, 10, 0, 0)
    permission_granted = datetime(2025, 9, 19, 10, 0, 0)
    permission_expires = datetime(2025, 11, 19, 10, 0, 0)

    return {
        "from_date": from_date.isoformat(),
        "to_date": to_date.isoformat(),
        "permission_granted": permission_granted.isoformat(),
        "permission_expires": permission_expires.isoformat(),
        "service_url": "https://api.example.com",
        "account": "test-account-123",
        "fapi_id": "fapi-transaction-456",
        "cap_member": "cap-member-789",
        "origin_url": "https://www.smartdcc.co.uk/",
        "origin_license_url": "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
    }


def create_cap_test_request(edp_data_attachment: dict):
    """Create a valid CAP test request payload."""
    now = datetime.now()

    return {
        "edp_data_attachment": edp_data_attachment,
        "cap_member_id": "cap-member-789",  # Must match the EDP record's "to" field
        "bank_member_id": "https://directory.core.trust.ib1.org/member/71212388",
        "cap_account": "cap-account-456",
        "cap_permission_granted": "2025-09-20T10:00:00",
        "cap_permission_expires": "2026-10-20T10:00:00",
        "grid_intensity_origin": "https://api.carbonintensity.org.uk/",
        "grid_intensity_license": "https://creativecommons.org/licenses/by/4.0/",
        "postcode": "CF99",
        "edp_service_url": "https://api.example.com",  # Must match the EDP record's "service" field
        "edp_member_id": "https://member.core.sandbox.trust.ib1.org/m/4tnapijm",
        "bank_service_url": "https://api.cap.example.com/emission-report/23",
        "from_date": "2025-09-20T10:00:00",
        "to_date": "2025-10-19T10:00:00",
    }


def test_sign_edp_endpoint():
    """Test the sign/edp endpoint with a valid request."""
    url = f"{BASE_URL}{EDP_ENDPOINT}"
    payload = create_edp_test_request()

    print(f"Testing EDP endpoint: {url}")
    print(f"Request payload:")
    print(json.dumps(payload, indent=2))
    print("\n" + "=" * 50 + "\n")

    try:
        response = requests.post(
            url, json=payload, headers={"Content-Type": "application/json"}, timeout=30
        )

        print(f"Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")

        if response.status_code == 200:
            print("✅ Success! EDP provenance record created.")

            edp_data = response.json()
            print(f"EDP data type: {type(edp_data)}")
            if isinstance(edp_data, dict):
                print(f"EDP data keys: {list(edp_data.keys())}")
            with open("edp_provenance_record.json", "w") as f:
                json.dump(edp_data, f, indent=2)
            return edp_data
        else:
            print("❌ Error occurred:")
            print(f"Status Code: {response.status_code}")
            try:
                error_detail = response.json()
                print(f"Error Details: {json.dumps(error_detail, indent=2)}")
            except:
                print(f"Error Text: {response.text}")
            return None

    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Could not connect to the server.")
        print("Make sure the provenance service is running on the specified URL.")
        return None
    except requests.exceptions.Timeout:
        print("❌ Timeout: Request took too long to complete.")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None


def test_sign_cap_endpoint(edp_data_attachment: dict):
    """Test the sign/cap endpoint with a valid request."""
    url = f"{BASE_URL}{CAP_ENDPOINT}"
    payload = create_cap_test_request(edp_data_attachment)

    print(f"\nTesting CAP endpoint: {url}")
    payload_copy = payload.copy()

    try:
        response = requests.post(
            url, json=payload, headers={"Content-Type": "application/json"}, timeout=30
        )

        print(f"Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")

        if response.status_code == 200:
            response_data = response.json()

            # Check if the response contains an error
            if "error" in response_data:
                print("❌ Error in CAP endpoint response:")
                print(f"Error: {response_data.get('error', 'Unknown error')}")
                print(f"Type: {response_data.get('type', 'Unknown type')}")
                if "traceback" in response_data:
                    print(f"Traceback: {response_data['traceback']}")
                return None

            print("✅ Success! CAP provenance record created.")
            print(f"Response size: {len(response.content)} bytes")
            print(f"Response type: {response.headers.get('content-type', 'unknown')}")

            # Save the response to a file
            with open("cap_provenance_record.json", "w") as f:
                json.dump(response_data, f, indent=2)
            print("Saved CAP provenance record to 'cap_provenance_record.json'")
            return response_data

        else:
            print("❌ Error occurred:")
            print(f"Status Code: {response.status_code}")
            try:
                error_detail = response.json()
                print(f"Error Details: {json.dumps(error_detail, indent=2)}")
            except:
                print(f"Error Text: {response.text}")
            return None

    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Could not connect to the server.")
        print("Make sure the provenance service is running on the specified URL.")
        return None
    except requests.exceptions.Timeout:
        print("❌ Timeout: Request took too long to complete.")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None


def test_both_endpoints():
    """Test both EDP and CAP endpoints in sequence."""
    print("🚀 Starting provenance service endpoint tests...")
    print("=" * 60)

    # Test EDP endpoint first
    edp_data = test_sign_edp_endpoint()
    print(f"EDP data type: {type(edp_data)}")
    if edp_data:
        # Test CAP endpoint with EDP data
        cap_data = test_sign_cap_endpoint(edp_data)

        if cap_data:
            print("\n🎉 All tests completed successfully!")
            print("📁 Generated files:")
        else:
            print("\n❌ CAP endpoint test failed")
    else:
        print("\n❌ EDP endpoint test failed - skipping CAP test")


if __name__ == "__main__":
    test_both_endpoints()
