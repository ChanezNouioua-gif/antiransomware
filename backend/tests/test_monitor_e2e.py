"""Tests du monitor : le simulateur doit déclencher une alerte, les scénarios bénins non."""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from app.config import Settings
from app.monitor.canary import CanaryManager
from app.monitor.detectors import shannon_entropy
from app.monitor.watcher import FileWatcher

SIM = Path(__file__).resolve().parents[1] / "scripts" / "ransomware_simulator.py"


def sim(*args: str) -> None:
    subprocess.run([sys.executable, str(SIM), *args], check=True, capture_output=True)


@pytest.fixture
def env(tmp_path):
    sandbox = tmp_path / "work" / "watched"
    sim("init", "--dir", str(sandbox), "--count", "100")
    canary = CanaryManager(sandbox / ".canary")
    canary.deploy()
    settings = Settings(
        _env_file=None,
        watched_paths=[sandbox],
        canary_dir=sandbox / ".canary",
        window_seconds=2.0,
        dedup_cooldown_seconds=30.0,
    )
    alerts, got = [], threading.Event()

    def on_alert(a):
        alerts.append(a)
        got.set()

    w = FileWatcher(settings, on_alert, canary)
    w.start()
    time.sleep(0.5)  # laisse l'observer s'installer
    yield sandbox, alerts, got
    w.stop()


def test_entropy_bounds():
    assert shannon_entropy(os.urandom(65536)) > 7.9
    assert shannon_entropy(b"bonjour " * 500) < 3.0


def test_encryption_triggers_one_alert(env):
    sandbox, alerts, got = env
    sim("encrypt", "--dir", str(sandbox), "--delay", "0.005")
    assert got.wait(6), "aucune alerte pour une simulation de chiffrement massif"
    time.sleep(2.5)  # le burst ne doit PAS produire d'alertes supplémentaires (dédup)
    assert len(alerts) == 1
    a = alerts[0]
    assert "high_entropy" in a.triggered_rules
    assert "extension_change" in a.triggered_rules or "mass_rename" in a.triggered_rules
    assert a.severity_hint.value in ("high", "critical")
    assert a.signals.files_modified >= 20
    assert ".locked" in a.signals.new_extensions


@pytest.mark.parametrize("scenario", ["benign-zip", "benign-copy", "benign-edit"])
def test_benign_activity_is_silent(env, scenario):
    sandbox, alerts, got = env
    sim(scenario, "--dir", str(sandbox), "--delay", "0.002")
    time.sleep(3.5)  # > fenêtre + intervalle d'évaluation
    assert alerts == [], f"faux positif sur {scenario}: {[a.triggered_rules for a in alerts]}"


def test_canary_touch_alerts_immediately(env):
    sandbox, alerts, got = env
    (sandbox / ".canary" / "!_documents_importants.txt").write_bytes(b"chiffre" * 100)
    assert got.wait(4)
    assert "canary_touched" in alerts[0].triggered_rules
