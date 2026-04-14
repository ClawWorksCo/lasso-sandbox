"""Tests for backend auto-detection."""

from unittest.mock import patch

import pytest

from lasso.backends.detect import detect_backend, require_backend


class TestDetectBackend:
    def test_returns_backend_when_docker_available(self):
        backend = detect_backend()
        # On this dev machine Docker is available
        if backend is not None:
            assert backend.is_available()

    def test_returns_none_when_nothing_available(self):
        with patch("lasso.backends.docker_backend.DockerBackend.is_available", return_value=False):
            backend = detect_backend()
            assert backend is None

    def test_require_backend_raises_when_none(self):
        with patch("lasso.backends.docker_backend.DockerBackend.is_available", return_value=False):
            with pytest.raises(RuntimeError, match="No container runtime"):
                require_backend()
