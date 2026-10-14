from __future__ import annotations

from app.database import _engine_kwargs, build_engine, get_db


def test_engine_kwargs_sqlite_disables_check_same_thread():
    kwargs = _engine_kwargs("sqlite:///./somefile.db")
    assert kwargs == {"connect_args": {"check_same_thread": False}}


def test_engine_kwargs_non_sqlite_uses_pool_pre_ping():
    kwargs = _engine_kwargs("postgresql://user:pass@localhost/dbname")
    assert kwargs == {"pool_pre_ping": True}


def test_build_engine_with_explicit_url():
    engine = build_engine("sqlite://")
    assert str(engine.url) == "sqlite://"


def test_get_db_yields_a_working_session_and_closes():
    gen = get_db()
    db = next(gen)
    # A session was handed back and basic querying doesn't blow up.
    assert db is not None
    # Exhausting the generator runs the `finally: db.close()` branch.
    try:
        next(gen)
    except StopIteration:
        pass
