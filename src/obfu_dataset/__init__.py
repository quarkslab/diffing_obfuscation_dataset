from pathlib import Path
import json
from dataclasses import dataclass

from .types import *
from .dataset import ObfuDataset
from .obfuscators import supported_passes

__version__ = "0.1.0"

PRECOMPILED_FILE = Path(__file__).parent / "precompiled" / "links.json"

_precompiled = json.loads(PRECOMPILED_FILE.read_text())


@dataclass
class DownloadLink:
    project: Project
    type: BinaryType
    link: str
    size: int
    hash: str
    obfuscator: Obfuscator | None = None
    obpass: ObPass | None = None
    level: int | None = None

def get_download_link(project: Project,
                      type: BinaryType,
                      obfuscator: Obfuscator = None,
                      obpass: ObPass = None,
                      level: int = None) -> DownloadLink | None:
    try:
        if type == BinaryType.PLAIN:
            raw_item = _precompiled[project.value]["sources"]
            package = DownloadLink(**raw_item)
        elif type == BinaryType.OBFUSCATED:
            raw_item = _precompiled[project.value][type.value][obfuscator.value][obpass.value][str(level)]
            package = DownloadLink(**raw_item)
            package.obfuscator = obfuscator
            package.obpass = obpass
            package.level = level
        else:
            assert False
        package.project = Project(package.project)
        package.type = BinaryType(package.type)
        return package
    except KeyError:
        return None
