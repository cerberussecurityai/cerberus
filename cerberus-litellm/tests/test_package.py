from helpers import load_capture

import cerberus_litellm


def test_version():
    assert cerberus_litellm.__version__ == "0.1.0"


def test_fixtures_are_trimmed():
    capture = load_capture("chat")
    assert set(capture) == {"standard_logging_object", "response_obj", "start_time", "end_time"}
    assert capture["standard_logging_object"]["call_type"] == "acompletion"
