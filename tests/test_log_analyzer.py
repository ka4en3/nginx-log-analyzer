import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from log_analyzer.log_analyzer import (
    calculate_statistics,
    check_report_exists,
    default_config,
    find_latest_log,
    load_config,
    parse_log_line,
)


class TestConfig:
    def test_load_config_default(self) -> None:
        """Test loading config with default values"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            config_path = f.name

        try:
            config = load_config(config_path, default_config)
            assert config["REPORT_SIZE"] == default_config["REPORT_SIZE"]
            assert config["ERROR_THRESHOLD"] == default_config["ERROR_THRESHOLD"]
        finally:
            os.unlink(config_path)

    def test_load_config_override(self) -> None:
        """Default Values Overwriting Test"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"REPORT_SIZE": 500}, f)
            config_path = f.name

        try:
            config = load_config(config_path, default_config)
            assert config["REPORT_SIZE"] == 500
            assert (
                config["ERROR_THRESHOLD"] == default_config["ERROR_THRESHOLD"]
            )  # defualt value
        finally:
            os.unlink(config_path)

    def test_load_config_not_found(self) -> None:
        """Missing config test"""
        config_path = "/non/existent/config.json"
        config = load_config(config_path, default_config)
        assert config["REPORT_SIZE"] == default_config["REPORT_SIZE"]
        assert config["ERROR_THRESHOLD"] == default_config["ERROR_THRESHOLD"]


class TestLogParsing:
    def test_parse_valid_line(self) -> None:
        """Correct string parsing test"""
        line = (
            "1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "
            '"GET /api/v2/banner/25019354 HTTP/1.1" 200 927 '
            '"-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" '
            '"-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390'
        )

        result = parse_log_line(line)
        assert result is not None
        assert result["url"] == "/api/v2/banner/25019354"
        assert result["request_time"] == 0.390

    def test_parse_invalid_line(self) -> None:
        """Invalid string parsing test"""
        line = "invalid log line"
        result = parse_log_line(line)
        assert result is None


class TestLogFinder:
    def test_find_latest_log(self) -> None:
        """Last Log Search Test"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create log files
            Path(tmpdir, "nginx-access-ui.log-20170630").touch()
            Path(tmpdir, "nginx-access-ui.log-20170629.gz").touch()
            Path(tmpdir, "nginx-access-ui.log-20170701.gz").touch()
            Path(tmpdir, "some-other.log").touch()

            result = find_latest_log(tmpdir)
            assert result is not None
            assert result.date == datetime(2017, 7, 1)
            assert result.path.endswith("nginx-access-ui.log-20170701.gz")

    def test_find_latest_log_empty_dir(self) -> None:
        """Search test in empty directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = find_latest_log(tmpdir)
            assert result is None


class TestStatistics:
    def test_calculate_statistics(self) -> None:
        """Statistics calculation test"""
        log_entries = [
            {"url": "/api/v2/banner/1", "request_time": 0.1},
            {"url": "/api/v2/banner/1", "request_time": 0.2},
            {"url": "/api/v2/banner/2", "request_time": 0.3},
        ]

        stats = calculate_statistics(log_entries)

        assert len(stats) == 2
        assert stats["/api/v2/banner/1"]["count"] == 2
        assert stats["/api/v2/banner/1"]["time_sum"] == 0.3
        assert stats["/api/v2/banner/1"]["time_avg"] == 0.15
        assert stats["/api/v2/banner/1"]["time_max"] == 0.2
        assert stats["/api/v2/banner/1"]["time_med"] == 0.15


class TestReportCheck:
    def test_check_report_exists(self) -> None:
        """Report Existence Check Test"""
        with tempfile.NamedTemporaryFile() as f:
            assert check_report_exists(f.name) is True

        assert check_report_exists("/non/existent/file.html") is False
