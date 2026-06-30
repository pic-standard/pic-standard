import json
import sys

from jsonschema import ValidationError, validate


def validate_pic_proposal(schema_path, proposal_path):
    with open(schema_path, "r") as f:
        schema = json.load(f)

    with open(proposal_path, "r") as f:
        proposal = json.load(f)

    try:
        validate(instance=proposal, schema=schema)
        print("PASS: PIC Contract is Schema-Valid.")
    except ValidationError as e:
        print(f"FAIL: Schema Violation: {e.message}")
        sys.exit(1)


if __name__ == "__main__":
    # Usage:
    #   python validate_proposal.py ../schemas/proposal_schema.json
    #   ../examples/money_transfer.json
    validate_pic_proposal(sys.argv[1], sys.argv[2])
