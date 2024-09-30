from pathlib import Path
from typing import Iterable
import zipfile
import logging
import json

# from obfu_dataset import get_download_link
from obfu_dataset.obfuscators import supported_passes
from obfu_dataset.obfuscators.ollvm import OLLVM_PASS
from obfu_dataset.obfuscators.tigress import TIGRESS_PASS
from obfu_dataset.types import Project, Obfuscator, ObPass, Sample, \
                               Compiler, Architecture, OptimLevel, BinaryType, \
                               SEED_NUMBER, AVAILABLE_LEVELS

SOURCES = "sources"
OBFUSCATED = "obfuscated"


class ObfuDataset(object):
    def __init__(self, root_dir: str | Path):
        pass
        self.root_path: Path = Path(root_dir)

        self._init_dirs()

    def _init_dirs(self):

        for proj in Project:
            proj_dir = self.root_path / proj.value
            
            src_dir = proj_dir / SOURCES
            src_dir.mkdir(parents=True, exist_ok=True)
            
            obf_dir = proj_dir / OBFUSCATED
            
            for obfu in Obfuscator:
                obfu_dir = obf_dir / obfu.value
                # get the list of available passes
                passes = {
                    Obfuscator.TIGRESS: TIGRESS_PASS,
                    Obfuscator.OLLVM: OLLVM_PASS
                }[obfu]
                for ob_pass in passes:
                    ob_pass_dir = obfu_dir / ob_pass.value
                    ob_pass_dir.mkdir(parents=True, exist_ok=True)

    def add_source_zip(self, project: Project, zipfile: Path) -> bool:
        extract_dir = self.get_src_path(project).parent
        if self._unzip_into(zipfile, extract_dir):
            if list(extract_dir.iterdir()):
                # Files are now present in that directory
                return extract_dir
            else:
                logging.warning("can't find any files in the extracted directory")
                return False
        else:
            return False

    def _unzip_into(self, zip_file: Path, extract_dir: Path) -> bool:
        try:
            with zipfile.ZipFile(zip_file, 'r') as out:
                out.extractall(path=extract_dir)
            return True
        except zipfile.BadZipfile:
            logging.error("error in extracting the zip")
            return False

    def get_src_path(self, project: Project):
        return self.root_path / project.value / SOURCES

    def get_obfu_path(self, project: Project, obfuscator: Obfuscator, obfpass: ObPass):
        return self.root_path / project.value / OBFUSCATED / obfuscator.value / obfpass.value

    def add_obfuscated_zip(self, project: Project, obfuscator: Obfuscator, obpass: ObPass, zipfile: Path) -> bool:
        extract_dir = self.get_obfu_path(project, obfuscator, obpass).parent
        if self._unzip_into(zipfile, extract_dir):
            if list(extract_dir.iterdir()):
                # Files are now present in that directory
                return extract_dir
            else:
                logging.warning("can't find any files in the extracted directory")
                return False
        else:
            return False

    def get_plain_sample(self,
                         project: Project,
                         architecture: Architecture = None,
                         compiler: Compiler = None,
                         optims: OptimLevel = None):
        if architecture is None:
            architecture = Architecture.X86_64
        if compiler is None:
            compiler = Compiler.GCC
        if optims is None:
            optims = OptimLevel.O0
        return Sample(project=project,
                      type=BinaryType.PLAIN,
                      architecture=architecture,
                      compiler=compiler,
                      optimization=optims,
                      obfuscator=None,
                      obfpass=None,
                      level=-1,
                      seed=-1,
                      root_path=self.root_path)

    def iter_plain_samples(self,
                                projects: Project | list[Project] = [],
                                architectures: Architecture | list[Architecture] = [],
                                compilers: Compiler | list[Compiler] = [],
                                optims: OptimLevel | list[OptimLevel] = []) -> Iterable[Sample]:
        to_list = lambda x, typ, enu: [x] if isinstance(x, typ) else (x if x else enu)

        projects = to_list(projects, Project, Project)
        for proj in projects:
            architectures = to_list(architectures, Architecture, Architecture)
            for arch in architectures:
                compilers = to_list(compilers, Compiler, Compiler)
                for compiler in compilers:
                    optims = to_list(optims, OptimLevel, OptimLevel)
                    for optim in optims:
                        yield Sample(
                            project=proj,
                            type=BinaryType.PLAIN,
                            architecture=arch,
                            compiler=compiler,
                            optimization=optim,
                            obfuscator=None,
                            obfpass=None,
                            level=-1,
                            seed=-1,
                            root_path=self.root_path
                        )


    def iter_obfuscated_samples(self,
                                projects: Project | list[Project] = [],
                                obfuscators: Obfuscator | list[Obfuscator] = [],
                                passes: ObPass | list[ObPass] = [],
                                levels: int | list[int] = [],
                                architectures: Architecture | list[Architecture] = [],
                                compilers: Compiler | list[Compiler] = [],
                                optims: OptimLevel | list[OptimLevel] = []) -> Iterable[Sample]:
        to_list = lambda x, typ, enu: [x] if isinstance(x, typ) else (x if x else enu)

        projects = to_list(projects, Project, Project)
        for proj in projects:
            obfuscators = to_list(obfuscators, Obfuscator, Obfuscator)
            for obfu in obfuscators:
                passes = to_list(passes, ObPass, ObPass)
                for obfpass in (x for x in passes if x in supported_passes(obfu)):
                    levels = to_list(levels, int, AVAILABLE_LEVELS)
                    for level in levels:
                        architectures = to_list(architectures, Architecture, Architecture)
                        for arch in architectures:
                            compilers = to_list(compilers, Compiler, Compiler)
                            for compiler in compilers:
                                optims = to_list(optims, OptimLevel, OptimLevel)
                                for optim in optims:
                                    for seed in range(1, SEED_NUMBER+1):
                                        yield Sample(
                                            project=proj,
                                            type=BinaryType.OBFUSCATED,
                                            architecture=arch,
                                            compiler=compiler,
                                            optimization=optim,
                                            obfuscator=obfu,
                                            obfpass=obfpass,
                                            level=level,
                                            seed=seed,
                                            root_path=self.root_path
                                        )

    def _fetch_url(self, url: str) -> Path:
        pass

    def get_symbols(self, proj: Project) -> dict[int, str]:
        sample = self.get_plain_sample(proj)
        return json.loads(sample.symbols_file.read_text())

    def compile(self, sample: Sample) -> bool:
        match sample.type:
            case BinaryType.PLAIN:
                pass
                # TODO: todo
            case BinaryType.OBFUSCATED:
                pass
                # TODO

