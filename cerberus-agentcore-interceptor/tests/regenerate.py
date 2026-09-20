"""Rewrite the expected-event goldens from the input fixtures.

Run when the source-event contract changes: .venv/bin/python tests/regenerate.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from helpers import FIXTURES, case_names, load_case, map_case  # noqa: E402

from cerberus_agentcore_interceptor import envelope as env  # noqa: E402


def main() -> None:
    for name in case_names():
        parsed = env.parse(load_case(name)["input"])
        golden = FIXTURES / f"{name}.event.json"
        if parsed.phase != env.REQUEST or not parsed.supported_version:
            golden.unlink(missing_ok=True)
            continue
        golden.write_text(json.dumps(map_case(name), indent=2, sort_keys=True) + "\n")
        print(name)


if __name__ == "__main__":
    main()
