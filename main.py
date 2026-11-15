import hashlib
import hmac
import os
import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

def create_session() -> requests.Session:
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

def main() -> None:
    api_key = os.getenv("API_KEY")
    secret = os.getenv("WEBHOOK_SECRET")
    if not api_key or not secret:
        raise RuntimeError("Set API_KEY and WEBHOOK_SECRET in .env")

    with create_session() as session:
        response = session.get(
            "https://jsonplaceholder.typicode.com/users",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=20,
        )
        response.raise_for_status()
        users = response.json()

    for user in users[:5]:
        print(f"{user.get('id')} - {user.get('name')} - {user.get('email')}")

    first = users[0]
    address = first.get("address", {})
    geo = address.get("geo", {})
    company = first.get("company", {})
    city = address.get("city", "Not Available")
    latitude = geo.get("lat", "Not Available")
    zip_code = address.get("zip", "Not Available")
    company_name = company.get("name", "Not Available")
    print(f"City: {city} | Zip: {zip_code} | Latitude: {latitude} | Company: {company_name}")

    payload = b'{"event":"employee.created"}'
    valid_signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    tampered_signature = hmac.new(secret.encode(), b'{"event":"employee.deleted"}', hashlib.sha256).hexdigest()
    wrong_secret_signature = hmac.new(b"wrong-secret", payload, hashlib.sha256).hexdigest()
    print(
        "Valid: "
        f"{verify_signature(payload, valid_signature, secret)} | "
        f"Tampered: {verify_signature(b'{\"event\":\"employee.deleted\"}', valid_signature, secret)} | "
        f"Wrong secret: {verify_signature(payload, wrong_secret_signature, secret)}"
    )

if __name__ == "__main__":
    main()
