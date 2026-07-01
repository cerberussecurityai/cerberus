from cerberus_envoy_ai_gateway.spanfields import raw_client_ip

ATTR = "http.client_ip"


def test_raw_client_ip_takes_leftmost():
    assert raw_client_ip({ATTR: "203.0.113.7, 10.0.0.1"}, ATTR) == "203.0.113.7"


def test_raw_client_ip_skips_empty_leading_segment():
    # Malformed XFF with a leading comma must not lose the real client IP.
    assert raw_client_ip({ATTR: "  ,  10.0.0.1"}, ATTR) == "10.0.0.1"


def test_raw_client_ip_all_empty_is_none():
    assert raw_client_ip({ATTR: " , , "}, ATTR) is None


def test_raw_client_ip_missing_is_none():
    assert raw_client_ip({}, ATTR) is None
