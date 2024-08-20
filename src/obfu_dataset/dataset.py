from pathlib import Path
from typing import Iterable

from obfu_dataset.types import Project, Obfuscator, ObPass, Sample, \
                               Compiler, Architecture, OptimLevel, BinaryType, \
                               SEED_NUMBER

'''
root/
    project/
        sources/
        obfuscated/
            obfuscator/
                obfu-pass/
                    level/

'''


class ObfuDataset(object):
    def __init__(self, root_dir: str|Path, json_links: Path|None=None):
        pass
        self.root_path = root_dir
        # TODO initialize dataset


    def _init_dirs(self):
        # TODO: Create base structure
        pass

    def download_plain(self, project: Project) -> None:
        # TODO: BARRE PROGRESSION
        # TODO: raise si quelconque exception
        # TODO: récupérer lien .json
        # TODO: requests
        # TODO: unzip + rm du zip
        pass

    def download_obfuscated(self, project: Project, obfuscator: Obfuscator, obfpass: ObPass) -> None:
        # TODO: BARRE PROGRESSION
        # TODO: raise si quelconque exception
        # TODO: récupérer lien .json
        # TODO: requests
        # TODO: unzip + rm du zip
        pass

    def download_all(self) -> None:
        # TODO: BARRE PROGRESSION
        # TODO: calculer sum des size du json
        # TODO: Also download plain
        for proj in Project:
            for obf in Obfuscator:
                for obfpass in ObPass:
                    self.download_obfuscated(proj, obf, obfpass)


    def iter_obfuscated_samples(self,
                                projects: list[Project],
                                obfuscators: list[Obfuscator],
                                passes: list[ObPass],
                                levels: list[int],
                                architectures: list[Architecture],
                                compilers: list[Compiler],
                                optims: list[OptimLevel]) -> Iterable[Sample]:
        for proj in projects:
            for obfu in obfuscators:
                for obfpass in passes:
                    for level in levels:
                        for arch in architectures:
                            for compiler in compilers:
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

