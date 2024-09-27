from pathlib import Path
import json
from dataclasses import dataclass

from .types import *
from .dataset import ObfuDataset

__version__ = "0.1.0"

PRECOMPILED_FILE = Path(__file__).parent / "precompiled" / "links.json"

_precompiled = json.loads(PRECOMPILED_FILE.read_text())


@dataclass
class DownloadLink:
    link: str
    size: int
    hash: str


def get_download_link(project: Project,
                      type: BinaryType,
                      obfuscator: Obfuscator = None,
                      obpass: ObPass = None) -> DownloadLink|None:
    try:
        if type == BinaryType.PLAIN:
            return DownloadLink(**_precompiled[project.value]["sources"])
        elif type == BinaryType.OBFUSCATED:
            item = _precompiled[project.value][type.value][obfuscator.value][obpass.value]
            return DownloadLink(**item)
    except KeyError:
        return None
