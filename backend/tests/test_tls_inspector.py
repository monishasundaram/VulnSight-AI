from app.scanners.tls import inspect_tls


def test_tls_inspector_refuses_private_addresses_before_connector(monkeypatch):
    attempted = []
    def connect(address, timeout):
        attempted.append(address)
        raise AssertionError("connector must not be called for a private address")
    result = inspect_tls("example.com", allowed_hostnames=["example.com"], resolver=lambda host, port: ("127.0.0.1",), connector=connect)
    assert result.reachable is False
    assert result.error_class == "scope_or_dns"
    assert attempted == []
