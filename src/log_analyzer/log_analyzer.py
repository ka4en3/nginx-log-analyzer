#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import gzip
import json
import logging
import os
import re
import statistics
import sys
from collections import defaultdict, namedtuple
from datetime import datetime

# from pathlib import Path
from string import Template
from typing import Dict, Iterator, List, Optional

import structlog

# Настройка дефолтного конфига
default_config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./logs",
    "LOG_FILE": "./logs/script_log.json",
    "ERROR_THRESHOLD": 0.1,  # 10% ошибок
}

# Структура для информации о файле лога
LogFileInfo = namedtuple("LogFileInfo", ["path", "date", "extension"])

# Паттерн для парсинга логов ui_short
LOG_PATTERN = re.compile(
    r"(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) "
    r"(?P<remote_user>\S+) +(?P<http_x_real_ip>\S+) +\[(?P<time_local>[^\]]+)\] "
    r'"(?P<request>[^"]*)" '
    r"(?P<status>\d{3}) "
    r"(?P<body_bytes_sent>\d+) "
    r'"(?P<http_referer>[^"]*)" '
    r'"(?P<http_user_agent>[^"]*)" '
    r'"(?P<http_x_forwarded_for>[^"]*)" '
    r'"(?P<http_X_REQUEST_ID>[^"]*)" '
    r'"(?P<http_X_RB_USER>[^"]*)" '
    r"(?P<request_time>\d+\.\d+)"
)

# Паттерн для поиска файлов логов
LOG_FILE_PATTERN = re.compile(r"nginx-access-ui\.log-(\d{8})(\.gz)?$")


def setup_logging(log_file: Optional[str] = None) -> None:
    """Настройка структурированного логирования"""

    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Настройка стандартного логгера
    if log_file:
        logging.basicConfig(
            filename=log_file, level=logging.INFO, format="%(message)s", force=True
        )
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)


def load_config(config_path: str) -> Dict:
    """Загрузка и слияние конфигурации"""
    config = default_config.copy()

    logger = structlog.get_logger()

    if not os.path.exists(config_path):
        logger.info(f"Config file not found: {config_path}, using default config")
        return config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            file_config = json.load(f)
            config.update(file_config)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file: {e}")

    logger.info("config_loaded", config_path=config_path)
    return config


def find_latest_log(log_dir: str) -> Optional[LogFileInfo]:
    """Поиск последнего лога по дате в имени файла"""
    if not os.path.exists(log_dir):
        return None

    latest_log = None
    latest_date = None

    for filename in os.listdir(log_dir):
        match = LOG_FILE_PATTERN.match(filename)
        if match:
            date_str = match.group(1)
            try:
                log_date = datetime.strptime(date_str, "%Y%m%d")
                if latest_date is None or log_date > latest_date:
                    latest_date = log_date
                    extension = match.group(2) or ""
                    latest_log = LogFileInfo(
                        path=os.path.join(log_dir, filename),
                        date=log_date,
                        extension=extension,
                    )
            except ValueError:
                continue

    return latest_log


def parse_log_line(line: str) -> Optional[Dict]:
    """Парсинг одной строки лога"""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()

    # Извлекаем URL из request
    request_parts = data["request"].split()
    if len(request_parts) >= 2:
        url = request_parts[1]
    else:
        url = data["request"]

    return {"url": url, "request_time": float(data["request_time"])}


def parse_log_file(file_path: str, error_threshold: float) -> Iterator[Dict]:
    """Генератор для парсинга файла логов"""
    logger = structlog.get_logger()

    # Выбираем способ открытия файла
    if file_path.endswith(".gz"):
        file_opener = gzip.open
        mode = "rt"
    else:
        file_opener = open
        mode = "r"

    total_lines = 0
    error_lines = 0

    try:
        with file_opener(file_path, mode, encoding="utf-8") as f:
            for line in f:
                total_lines += 1
                parsed = parse_log_line(line)

                if parsed:
                    yield parsed
                else:
                    error_lines += 1

                # Периодическое логирование прогресса
                if total_lines % 100000 == 0:
                    logger.info(
                        "parse_progress",
                        total_lines=total_lines,
                        error_lines=error_lines,
                    )

    except Exception as e:
        logger.error("parse_error", error=str(e), file=file_path)
        raise

    # Проверка порога ошибок
    if total_lines > 0:
        error_rate = error_lines / total_lines
        if error_rate > error_threshold:
            logger.error(
                "error_threshold_exceeded",
                error_rate=error_rate,
                threshold=error_threshold,
                total_lines=total_lines,
                error_lines=error_lines,
            )
            raise ValueError(
                f"Error rate {error_rate:.2%} exceeds threshold {error_threshold:.2%}"
            )

    logger.info(
        "parse_complete",
        total_lines=total_lines,
        error_lines=error_lines,
        success_rate=1 - (error_lines / total_lines if total_lines > 0 else 0),
    )


def calculate_statistics(log_entries: List[Dict]) -> Dict[str, Dict]:
    """Расчет статистики по URL"""
    url_stats = defaultdict(lambda: {"count": 0, "time_sum": 0.0, "time_list": []})

    total_count = 0
    total_time = 0.0

    for entry in log_entries:
        url = entry["url"]
        request_time = entry["request_time"]

        url_stats[url]["count"] += 1
        url_stats[url]["time_sum"] += request_time
        url_stats[url]["time_list"].append(request_time)

        total_count += 1
        total_time += request_time

    # Вычисляем финальные метрики
    result = {}
    for url, stats in url_stats.items():
        time_list = stats["time_list"]
        result[url] = {
            "count": stats["count"],
            "count_perc": (
                round(stats["count"] / total_count * 100, 2) if total_count > 0 else 0
            ),
            "time_sum": round(stats["time_sum"], 3),
            "time_perc": (
                round(stats["time_sum"] / total_time * 100, 2) if total_time > 0 else 0
            ),
            "time_avg": (
                round(stats["time_sum"] / stats["count"], 3)
                if stats["count"] > 0
                else 0
            ),
            "time_max": round(max(time_list), 3) if time_list else 0,
            "time_med": round(statistics.median(time_list), 3) if time_list else 0,
        }

    return result


def generate_report(
    stats: Dict[str, Dict], report_size: int, template_path: str, output_path: str
) -> None:
    """Генерация HTML отчета"""
    logger = structlog.get_logger()

    # Сортировка по time_sum и ограничение размера
    sorted_urls = sorted(stats.items(), key=lambda x: x[1]["time_sum"], reverse=True)[
        :report_size
    ]

    # Подготовка данных для шаблона
    table_data = []
    for url, url_stats in sorted_urls:
        table_data.append({"url": url, **url_stats})

    # Чтение шаблона
    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    # Замена $table_json в шаблоне
    template = Template(template_content)
    report_content = template.safe_substitute(table_json=json.dumps(table_data))

    # Сохранение отчета
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    logger.info("report_generated", path=output_path)


def check_report_exists(report_path: str) -> bool:
    """Проверка существования отчета"""
    return os.path.exists(report_path)


def main() -> int:
    """Главная функция"""
    parser = argparse.ArgumentParser(description="Nginx log analyzer")
    parser.add_argument("--config", default="config.json", help="Path to config file")
    args = parser.parse_args()

    # Настройка логирования
    setup_logging()
    logger = structlog.get_logger()

    try:
        # Загрузка конфигурации
        config = load_config(args.config)
        # logger.info("config_loaded", config_path=args.config)

        # Настройка логирования с учетом конфига
        if config.get("LOG_FILE"):
            logger.info("logging_to_file", file=config["LOG_FILE"])
            setup_logging(config["LOG_FILE"])

        # Поиск последнего лога
        latest_log = find_latest_log(config["LOG_DIR"])
        if not latest_log:
            logger.info("no_logs_found", log_dir=config["LOG_DIR"])
            return 0

        logger.info(
            "latest_log_found",
            path=latest_log.path,
            date=latest_log.date.strftime("%Y-%m-%d"),
        )

        # Формирование пути к отчету
        report_filename = f"report-{latest_log.date.strftime('%Y.%m.%d')}.html"
        report_path = os.path.join(config["REPORT_DIR"], report_filename)

        # Проверка существования отчета
        if check_report_exists(report_path):
            logger.info("report_already_exists", path=report_path)
            return 0

        # Парсинг лога
        logger.info("parsing_started", file=latest_log.path)
        log_entries = list(parse_log_file(latest_log.path, config["ERROR_THRESHOLD"]))

        # Расчет статистики
        logger.info("calculating_statistics", entries_count=len(log_entries))
        stats = calculate_statistics(log_entries)

        # Генерация отчета
        template_path = os.path.join("templates", "report.html")
        generate_report(stats, config["REPORT_SIZE"], template_path, report_path)

        logger.info("processing_complete", report_path=report_path)
        return 0

    except Exception as e:
        logger.error("fatal_error", error=str(e), exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
