import logging
from datetime import datetime
from pathlib import Path

from src.utils.utils import LOG_DIR


def _setup_logger(log_level: int) -> None:
    """
    Setting up logger such that a console handler forwards log statements to
    the console which match LOG_LEVEL (CL argument) and file handler which logs
    all messages independent of their log level.
    """
    logger = logging.getLogger(__package__)
    console_handler = logging.StreamHandler()
    date = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
    log_path = LOG_DIR / Path(f"{date}.log")
    if not log_path.parent.exists():
        log_path.parent.mkdir(parents=True)
    file_handler = logging.FileHandler(str(log_path))

    # set the log level of the LOGGER to debug such that no messages are discarded
    logger.setLevel(logging.DEBUG)
    # what is print in the console should match the level specified by -v{v}
    console_handler.setLevel(log_level)
    # in the file we want all log messages again
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter("%(asctime)s-%(name)s-%(levelname)s- %(message)s")
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)