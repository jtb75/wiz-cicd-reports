"""
Tests for logging configuration functionality.
"""

import pytest
import logging
from wiz_cicd import configure_logging


class TestLoggingConfiguration:
    """Tests for configure_logging function."""

    @pytest.mark.unit
    def test_configure_logging_sets_level(self):
        """Test that configure_logging sets the correct log level."""
        configure_logging(level='DEBUG')
        logger = logging.getLogger('wiz_cicd')
        assert logger.level == logging.DEBUG

    @pytest.mark.unit
    def test_configure_logging_default_level(self):
        """Test that configure_logging defaults to INFO."""
        configure_logging()
        logger = logging.getLogger('wiz_cicd')
        assert logger.level == logging.INFO

    @pytest.mark.unit
    def test_configure_logging_accepts_all_levels(self):
        """Test that configure_logging accepts all standard log levels."""
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

        for level in levels:
            configure_logging(level=level)
            logger = logging.getLogger('wiz_cicd')
            assert logger.level == getattr(logging, level)

    @pytest.mark.unit
    def test_configure_logging_custom_format(self):
        """Test that configure_logging accepts custom format."""
        custom_format = '%(levelname)s - %(message)s'

        # Should not raise any errors
        configure_logging(level='INFO', format=custom_format)

        # Verify logger is configured
        logger = logging.getLogger('wiz_cicd')
        assert logger.level == logging.INFO

    @pytest.mark.unit
    def test_configure_logging_case_insensitive(self):
        """Test that configure_logging handles lowercase level names."""
        configure_logging(level='debug')
        logger = logging.getLogger('wiz_cicd')
        assert logger.level == logging.DEBUG

        configure_logging(level='WaRnInG')
        assert logger.level == logging.WARNING
