from __future__ import annotations

import os
import shutil
from pathlib import Path

# Tests always use a disposable, versioned /tmp database and never the development SQLite file.
_test_db = Path("/tmp/vulnsight-phase-tests-v3.db")
for suffix in ("", "-wal", "-shm"):
    Path(str(_test_db) + suffix).unlink(missing_ok=True)
_test_db.parent.mkdir(parents=True, exist_ok=True)
_test_data = Path("/tmp/vulnsight-test-data-v3")
shutil.rmtree(_test_data, ignore_errors=True)
_test_data.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:////{_test_db.as_posix().lstrip('/')}"
os.environ["DATA_DIR"] = str(_test_data)
os.environ["SESSION_SECRET"] = "test-only-session-secret-32-bytes-minimum-value"
os.environ["APP_ENV"] = "test"
os.environ["COOKIE_SECURE"] = "false"
os.environ["COOKIE_SAMESITE"] = "lax"


import pytest


@pytest.fixture(autouse=True)
def reset_process_local_rate_limits():
    # The in-memory limiter is process-scoped in production; independent test cases must not share its counters.
    from app.core.rate_limit import limiter

    with limiter._lock:
        limiter._events.clear()
    yield
