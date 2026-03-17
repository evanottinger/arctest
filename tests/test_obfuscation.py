import base64


def test_base64_exec():
    """Obfuscated payload execution."""
    payload = base64.b64decode("cHJpbnQoJ2hlbGxvJyk=")
    exec(payload)
    assert True
