import pytest

from phishstream import config

pytestmark = pytest.mark.skipif(not config.MODEL_PATH.exists(), reason="run `python -m phishstream.pipeline` first")


def test_api_check_and_live():
    from fastapi.testclient import TestClient
    from phishstream.api.app import app
    with TestClient(app) as c:
        r = c.post("/api/check", json={"url": "http://sbi-kyc-update12.xyz/login"}).json()
        assert r["verdict"] in ("known_phishing", "likely_phishing")
        assert c.post("/api/check", json={"url": "https://www.hdfcbank.com/personal"}).json()["verdict"] == "clean"
        s = c.get("/api/live").json()
        assert s["events"] >= 2 and "dgim" in s and "hll" in s
        assert c.get("/api/insights").status_code == 200
