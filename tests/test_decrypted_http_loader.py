from __future__ import annotations

import json

from capture.decrypted_http_loader import DecryptedHttpLoader


def test_decrypted_http_loader_reads_jsonl(tmp_path):
    log_path = tmp_path / "decrypted.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-01-01 00:00:00.000",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "src_port": 51000,
                "dst_port": 443,
                "method": "GET",
                "host": "example.test",
                "path": "/search",
                "headers": {"User-Agent": "course-lab"},
                "body_preview": "",
                "source": "authorized lab proxy",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    records = list(DecryptedHttpLoader().load(log_path))

    assert len(records) == 1
    assert records[0].method == "GET"
    assert records[0].host == "example.test"
    assert records[0].headers["User-Agent"] == "course-lab"
    assert records[0].source == "authorized lab proxy"


def test_decrypted_http_loader_reads_csv_with_json_headers(tmp_path):
    log_path = tmp_path / "decrypted.csv"
    log_path.write_text(
        "timestamp,src_ip,dst_ip,src_port,dst_port,method,host,path,headers,body_preview,source\n"
        "2026-01-01 00:00:00.000,192.168.1.10,192.168.1.20,51000,443,POST,"
        'example.test,/login,"{""Content-Type"": ""application/json""}",'
        '"{""user"": ""demo""}",authorized lab proxy\n',
        encoding="utf-8",
    )

    records = list(DecryptedHttpLoader().load(log_path))

    assert len(records) == 1
    assert records[0].method == "POST"
    assert records[0].dst_port == 443
    assert records[0].headers["Content-Type"] == "application/json"
    assert records[0].body_preview == '{"user": "demo"}'
