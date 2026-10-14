from __future__ import annotations


def test_sync_endpoint_parses_and_creates(client, test_settings, tmp_path):
    log_path = tmp_path / "alert"
    log_path.write_text(
        "10/04-12:34:56.789012  [**] [1:1000001:1] ICMP Test Rule Triggered [**] "
        "[Classification: Potentially Bad Traffic] [Priority: 2] {ICMP} 10.0.0.5 -> 10.0.0.10\n"
    )
    test_settings.snort_alert_log_path = str(log_path)

    resp = client.post("/api/v1/snort/sync")
    assert resp.status_code == 200
    body = resp.json()
    assert body["created"] == 1
    assert body["parsed"] == 1

    resp2 = client.post("/api/v1/snort/sync")
    assert resp2.json()["skipped_duplicates"] == 1
