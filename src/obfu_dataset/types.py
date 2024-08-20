from pathlib import Path
from enum import Enum, auto
from dataclasses import dataclass

SEED_NUMBER=10

class BinaryType(Enum):
    PLAIN = "plain"
    OBFUSCATED = "obfuscated"

class Obfuscator(Enum):
    TIGRESS = "tigress"
    OLLVM = "ollvm"

class Compiler(Enum):
    CLANG = "clang"
    GCC = "gcc"

class ObPass(Enum):
    COPY = "copy"
    MERGE = "merge"
    SPLIT = "split"
    CFF = "CFF"
    OPAQUE = "opaque"
    VIRTUALIZE = "virtualize"
    ENCODEARITH = "encodearith"
    ENCODELITERAL = "encodeliteral"
    CFF_ENCODEARITH_OPAQUE = "mix-1"
    CFF_ENCODEARITH_OPAQUE_SPLIT = "mix-2"

class Project(Enum):
    ZLIB = "zlib"
    LZ4 = "lz4"
    MINILUA = "minilua"
    SQLITE = "sqlite"
    FREETYPE = "freetype"

class Architecture(Enum):
    X86_64 = "X86_64"
    ARM = "ARM"
    AARCH64 = "Aarch64"

class OptimLevel(Enum):
    O0 = "-O0"
    O1 = "-O1"
    O2 = "-O2"
    O3 = "-O3"
    OS = "-OS"


NOT_EXISTING_BENCH = [
    (Project.MINILUA, Obfuscator.TIGRESS, ObPass.MERGE),
    (Project.SQLITE, Obfuscator.TIGRESS, ObPass.MERGE),
    (Project.SQLITE, Obfuscator.TIGRESS, ObPass.OPAQUE),
    (Project.FREETYPE, Obfuscator.TIGRESS, ObPass.VIRTUALIZE)
]

'''
PARTIAL
* minilua / tigress / virtualize / 80 / [3/10] (manquant)
* sqlite / tigress / virtualize / 20 / [1/10]  (manquant)
                                / 30 / [2/10]
                                / 40 / [2/10]
                                / 50 / [2/10]
                                / 60 / [3/10]
                                / 70 / [4/10]
                                / 80 / [3/10]
                                / 90 / [4/10]
'''


@dataclass
class Sample:
    project: Project
    type: BinaryType
    architecture: Architecture
    compiler: Compiler
    optimization: OptimLevel
    obfuscator: Obfuscator | None
    obfpass: ObPass | None
    level: int
    seed: int
    root_path: Path

    @property
    def basename(self) -> str:
        '''
        Name mangling in source:
            [project]_[compiler]_[optim].c etc..
        Name mangling in binaries:
            [project]_[obfuscator]_[compiler]_[obfpass]_[level]_[seed]_[optim].c
        '''
        match self.type:
            case BinaryType.PLAIN:
                pass # TODO:
            case BinaryType.OBFUSCATED:
                pass # TODO

    @property
    def base_dir(self) -> Path:
        match self.type:
            case BinaryType.PLAIN:
                return self.root_path / self.project.value / "sources"
            case BinaryType.OBFUSCATED:
                obfu_p = self.root_path / self.project.value / "obfuscated"
                obfu_p = obfu_p / self.obfuscator.value / self.obfpass.value
                return obfu_p / str(self.level)

    @property
    def binary_file(self) -> Path:
        return self.base_dir / (self.basename+".exe")

    @property
    def binexport_file(self) -> Path:
        return self.base_dir / (self.basename + ".BinExport")

    @property
    def quokka_file(self) -> Path:
        return self.base_dir / (self.basename + ".Quokka")

    @property
    def source_file(self) -> Path:
        return self.base_dir / (self.basename + ".c")

    @property
    def symbols_file(self) -> Path:
        return self.base_dir / (self.basename + ".json")

    def is_downloaded(self) -> bool:
        return self.base_dir.exists()

    @property
    def exists(self) -> bool:
        return self.base_dir.exists() and self.binary_file.exists()
