from __future__ import annotations

import argparse
import re
from pathlib import Path


BUSINESSES = (
    "codestra",
    "moneybee",
    "beyvra",
    "breero",
    "larim-a",
    "transportation",
    "booked4seasons",
    "social",
    "klyrow",
    "telnexa",
    "kyqra",
    "restaurant",
    "provisioning",
)
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def render(business: str) -> str:
    if not SLUG.fullmatch(business):
        raise ValueError(f"invalid business slug: {business}")
    blocks = [
        f'''path "secret/data/observability/clients/{business}/alloy" {{
  capabilities = ["read"]
}}''',
        f'''path "secret/data/observability/clients/{business}/opentelemetry" {{
  capabilities = ["read"]
}}''',
        f'''path "pki_observability/issue/telemetry-client-{business}" {{
  capabilities = ["create", "update"]
}}''',
        '''path "auth/token/lookup-self" {
  capabilities = ["read"]
}''',
        '''path "auth/token/renew-self" {
  capabilities = ["update"]
}''',
        '''path "sys/leases/renew" {
  capabilities = ["update"]
}''',
    ]
    if business == "beyvra":
        blocks.extend(
            [
                '''path "secret/data/businesses/beyvra/trading/*" {
  capabilities = ["deny"]
}''',
                '''path "transit/sign/beyvra-*" {
  capabilities = ["deny"]
}''',
                '''path "transit/decrypt/beyvra-*" {
  capabilities = ["deny"]
}''',
                '''path "database/creds/beyvra-trading-*" {
  capabilities = ["deny"]
}''',
            ]
        )
    return "\n\n".join(blocks) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for business in BUSINESSES:
        destination = args.output_dir / f"telemetry-{business}.hcl"
        destination.write_text(render(business), encoding="utf-8")


if __name__ == "__main__":
    main()
