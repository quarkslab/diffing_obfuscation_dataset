import json
from pathlib import Path
from enum import Enum, auto
from dataclasses import dataclass

SEED_NUMBER = 10

class BinaryType(Enum):
    PLAIN = "plain"
    OBFUSCATED = "obfuscated"

class Obfuscator(Enum):
    TIGRESS = "tigress"
    OLLVM = "ollvm"

class Compiler(Enum):
    CLANG = "clang14"
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
    CFF_ENCODEARITH_OPAQUE = "mix1"
    CFF_ENCODEARITH_OPAQUE_SPLIT = "mix2"

class Project(Enum):
    ZLIB = "zlib"
    LZ4 = "lz4"
    MINILUA = "minilua"
    SQLITE = "sqlite"
    FREETYPE = "freetype"

class Architecture(Enum):
    X86_64 = "x64"
    # ARM = "ARM"
    # AARCH64 = "Aarch64"

class OptimLevel(Enum):
    O0 = "O0"
    # O1 = "O1"
    O2 = "O2"
    # O3 = "O3"
    # OS = "OS"


NOT_EXISTING_BENCH = [
    (Project.MINILUA, Obfuscator.TIGRESS, ObPass.MERGE),
    (Project.SQLITE, Obfuscator.TIGRESS, ObPass.MERGE),
    (Project.SQLITE, Obfuscator.TIGRESS, ObPass.OPAQUE),
    (Project.FREETYPE, Obfuscator.TIGRESS, ObPass.VIRTUALIZE)
]

AVAILABLE_LEVELS = [
    10,
    20,
    30,
    40,
    50,
    60,
    70,
    80,
    90,
    100
]

'''
PARTIAL
* minilua / tigress / virtualize / 80 / [3/10] (manquant)

* sqlite / tigress / virtualize / 20 / [1/10]  
                                / 30 / [2/10]
                                / 40 / [2/10]
                                / 50 / [2/10]
                                / 60 / [3/10]
                                / 70 / [4/10]
                                / 80 / [3/10]
                                / 90 / [4/10]
                            
* sqlite / tigress / mix1 / 10 / [1/10]
                            20 / [1/10]
                            30 / [3/10]
                            60 / [1/10]
                            70 / [4/10]
                            80 / [1/10]
                            90 / [3/10]
                            100 / [5/10]
                            
* sqlite / tigress / mix2 / 10 / [1/10]
                            20 / [1/10]
                            30 / [3/10]
                            60 / [1/10]
                            70 / [4/10]
                            80 / [1/10]
                            90 / [3/10]
                            100 / [5/10]

* freetype / tigress / merge / 100 / [10/10] (all of them are missing)

* freetype / tigress / opaque / 10 / [3/10]
                              / 20 / [5/10]
                              / 30 / [5/10]
                              / 40 / [8/10]
                              / 50 / [9/10]
                              / 60 / [8/10]
                              / 70 / [8/10]
                              / 80 / [10/10]
                              / 90 / [9/10]
                              / 100 / [9/10]
                              
* freetype / tigress / mix1 / 20 / [1/10]
                              30 / [1/10]
                              50 / [1/10]
                              70 / [2/10]
                              80 / [1/10]
                              90 / [1/10]
                              100 / [1/10]
                              
* freetype / tigress / mix2 / 20 / [1/10]
                              30 / [1/10]
                              50 / [1/10]
                              70 / [2/10]
                              80 / [1/10]
                              90 / [1/10]
                              100 / [1/10]

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
    def basename_bin(self) -> str:
        """
        Return the name of a sample (without extension!)

        Name mangling for binaries:
            Plain : [project]_[compiler]_[archi]_[optim].exe
            Obfuscated : [project]_[obfuscator]_[compiler]_[archi]_[obfpass]_[level]_[seed]_[optim].exe
        """
        match self.type:
            case BinaryType.PLAIN:
                return (f"{self.project.value}_{self.compiler.value}_"
                        f"{self.architecture.value}_{self.optimization.value}")
            case BinaryType.OBFUSCATED:
                return (f"{self.project.value}_{self.obfuscator.value}_{self.compiler.value}_"
                        f"{self.architecture.value}_{self.obfpass.value}_{self.level}_{self.seed}_{self.optimization.value}")

    @property
    def basename_src(self) -> str:
        """
        Return the name of a source file (without extension)

        Name mangling for src
            Plain : [project].c
            Obfuscated : [project]_[obfuscator]_[compiler]_[archi]_[obfpass]_[level]_[seed].c  #Including compiler and archi is meaningful for Tigress
        """
        match self.type:
            case BinaryType.PLAIN:
                return f"{self.project.value}"
            case BinaryType.OBFUSCATED:
                return (f"{self.project.value}_{self.obfuscator.value}_{self.compiler.value}_"
                       f"{self.architecture.value}_{self.obfpass.value}_{self.level}_{self.seed}")

    @property
    def base_dir(self) -> Path:
        """
        Return the base directory for the sample (whether its a source or a binary one)
        """
        match self.type:
            case BinaryType.PLAIN:
                return self.root_path / self.project.value / "sources"
            case BinaryType.OBFUSCATED:
                obfu_p: Path = self.root_path / self.project.value / "obfuscated"
                obfu_p = obfu_p / self.obfuscator.value / self.obfpass.value
                return obfu_p / str(self.level)

    @property
    def binary_file(self) -> Path:
        return self.base_dir / (self.basename_bin +".exe")

    @property
    def binexport_file(self) -> Path:
        return self.base_dir / (self.basename_bin + ".BinExport")

    @property
    def quokka_file(self) -> Path:
        return self.base_dir / (self.basename_bin + ".Quokka")

    @property
    def source_file(self) -> Path:
        return self.base_dir / (self.basename_src + ".c")

    @property
    def symbols_file(self) -> Path:
        return self.base_dir / (self.basename_bin + ".json")
    
    @property
    def h_file(self) -> Path:
        if self.project.value == 'minilua':
            return self.base_dir / self.basename_bin.with_suffix(".h")
        else:
            return self.base_dir / (self.project.value + ".h") 
        
    def get_symbols(self) -> dict[int, str]:
        return json.loads(self.symbols_file.read_text())

    @property
    def exists(self) -> bool:
        return self.source_file.exists()
