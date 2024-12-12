import pytest
from app import detect_phishing, submit_report

def test_detect_phishing():
    url = "http://example-phish-site.com"
    assert detect_phishing(url) == True

def test_submit_report():
    report = submit_report("http://example-phish-site.com", "Suspicious behavior")
    assert report["status"] == "success"

