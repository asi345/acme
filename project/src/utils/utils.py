import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)

SRC_DIR = Path(__file__).parent.parent.parent.resolve()
DATA_DIR = SRC_DIR / "data"
