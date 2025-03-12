import logging
import os
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

class Phish_Logger:
    @staticmethod
    def get_phish_logger(name):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)

        dir_name = os.path.abspath(os.path.dirname(__file__))
        Path(os.path.join(dir_name, 'Crawling_logs')).mkdir(parents=True, exist_ok=True)
        log_filepath = os.path.join(dir_name, 'Crawling_logs', 'phish_logger.log')

        # TimedRotatingFileHandler
        handler = TimedRotatingFileHandler(
            log_filepath, when="midnight", interval=1, encoding="utf-8"
        )
        handler.suffix = "%Y-%m-%d"  # This ensures new log files have the date in their name

        # Set logging format
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        # Avoid duplicate handlers
        if not logger.handlers:
            logger.addHandler(handler)

        return logger
