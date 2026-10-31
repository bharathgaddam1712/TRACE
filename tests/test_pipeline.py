"""End-to-end: run the real pipeline on the organiser sample and on planted attack chains."""
import json
import shutil

import pytest
from fastapi.testclient import TestClient

from conftest import SAMPLE
from tracekc.api import create_app
from tracekc.config import load_config
from tracekc.evaluate import evaluate, gt_from_labels
from tracekc.pipeline import run_pipeline
from tracekc.synth import scale_up, write_planted


@pytest.fixture(scope="module")
def dense(tmp_path_factory):
    """~50 MB: 6 replays of the sample spread over 8 h (noise recurs hourly) + one planted chain."""
    base = tmp_path_factory.mktemp("dense")
    scale_up(SAMPLE, base / "in", target_gb=0.05)
    out = base / "out"
    report = run_pipeline(load_config(), base / "in", out)
    gt = json.loads((base / "in_gt.json").read_text())
    return out, report, gt


def test_sigma_rules_reproduce_every_labelled_sample_alert(tmp_path):
    cfg = load_config(overrides=["detection.use_vendor_alerts=false"])
    run_pipeline(cfg, SAMPLE, tmp_path / "out")
    res = evaluate(tmp_path / "out", gt_from_labels(SAMPLE))
    assert res["any"]["detection_rate"] == 1.0
    assert res["any"]["label_accuracy_strict"] == 1.0


def test_planted_chain_rebuilt_in_order_inside_dense_noise(dense):
    out, report, gt = dense
    res = evaluate(out, gt)
    assert res["incident"]["detection_rate"] == 1.0
    assert res["incident"]["label_accuracy_strict"] == 1.0
    assert res["incident"]["path_rate"] == 1.0
    assert res["false_incident_rate"] == 0.0
    inc = json.loads((out / "incidents" / "1.json").read_text())
    assert [s["technique"] for s in inc["timeline"]] == ["T1110", "T1059.001", "T1547.001", "T1071.001",
                                                         "T1021.001", "T1048"]
    assert inc["host_path"] == ["WS-HR-012", "SRV-FILE-01"]
    # Shared entities establish association; only specific process/logon evidence is observed.
    assert all(s['links'] for s in inc['timeline'][1:])
    assert all(link['event_ids'] for link in inc['correlation_links'])
    assert all(link['kind'] == ('observed' if link['relation'] in {'lateral', 'process_entity'} else 'inferred')
               for link in inc['correlation_links'])
    assert inc["lookahead"]["status"] == "evidenced"


def test_noise_is_not_promoted_and_not_dropped(dense):
    out, report, _ = dense
    assert report["output"]["incidents"] == 1
    assert report["signals"]["recurrent_signals"] > 0
    findings = json.loads((out / "findings.json").read_text())
    assert findings["total_isolated_signals"] == report["output"]["isolated_signals"] > 0


def test_planted_chain_found_next_to_raw_sample(tmp_path):
    inp = tmp_path / "in"
    inp.mkdir()
    shutil.copy(SAMPLE, inp / "sample.json")
    _, gt_path = write_planted(inp)
    gt = json.loads(gt_path.read_text())
    gt_path.unlink()
    run_pipeline(load_config(), inp, tmp_path / "out")
    res = evaluate(tmp_path / "out", gt)
    assert res["incident"]["detection_rate"] == 1.0
    assert res["incident"]["path_rate"] == 1.0


def test_api_serves_precomputed_path(dense):
    out, _, _ = dense
    client = TestClient(create_app(out))
    assert client.get("/health").json()["incidents"] == 1
    body = client.get("/incidents/1/path").json()
    assert body["host_path_text"] == "WS-HR-012 -> SRV-FILE-01"
    assert client.get("/incidents/999").status_code == 404
    assert "Step 6" in client.get("/incidents/1/report").text
