from __future__ import annotations

import io
import json
import logging
import sys

from app.logging_config import JsonFormatter, configure_logging, get_logger


def test_json_formatter_basic_fields():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    payload = json.loads(formatter.format(record))
    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "test.logger"


def test_json_formatter_includes_exception_info():
    formatter = JsonFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="failed",
            args=(),
            exc_info=sys.exc_info(),
        )
    payload = json.loads(formatter.format(record))
    assert "exception" in payload
    assert "ValueError" in payload["exception"]


def test_json_formatter_stringifies_non_json_serializable_extra():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="has odd extra",
        args=(),
        exc_info=None,
    )
    record.weird = object()  # not JSON serializable
    payload = json.loads(formatter.format(record))
    assert isinstance(payload["weird"], str)


def test_configure_logging_plain_text_formatter():
    configure_logging(log_level="DEBUG", log_json=False)
    root = logging.getLogger()
    assert root.level == logging.DEBUG
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, logging.Formatter)
    assert not isinstance(root.handlers[0].formatter, JsonFormatter)
    # Restore JSON logging so other tests see the normal configuration.
    configure_logging(log_level="INFO", log_json=True)


def test_get_logger_returns_named_logger():
    logger = get_logger("my.module")
    assert logger.name == "my.module"
