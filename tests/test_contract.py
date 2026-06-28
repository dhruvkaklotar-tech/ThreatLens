import json
from jsonschema import validate

def test_api_contract():
    with open("docs/api-contract.schema.json", "r", encoding="utf-8") as f:
        schema = json.load(f)
    with open("docs/golden-response.json", "r", encoding="utf-8") as f:
        payload = json.load(f)
    validate(instance=payload, schema=schema)