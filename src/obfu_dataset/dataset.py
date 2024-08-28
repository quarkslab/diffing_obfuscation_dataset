from pathlib import Path
from typing import Iterable
from zipfile import ZipFile
import logging
import requests
import json
import hashlib

from obfu_dataset.types import Project, Obfuscator, ObPass, Sample, \
                               Compiler, Architecture, OptimLevel, BinaryType, \
                               SEED_NUMBER

OLLVM_PASS = [ObPass.CFF, ObPass.OPAQUE, ObPass.ENCODEARITH, ObPass.CFF_ENCODEARITH_OPAQUE]


class ObfuDataset(object):
    def __init__(self, root_dir: str|Path, json_links: Path|None=None):
        pass
        self.root_path = root_dir
        if json_links:
            self.json_links = json_links
        else:
            default_path = Path('precompiled/links.json')
            if default_path.exists():
                self.json_links = default_path
            else:
                logging.ERROR("Missing link .json file in the current directory. Please provide one")
                exit()
        self._init_dirs()


    def _init_dirs(self):
        
        root = Path(self.root_path)
        for proj in Project:
            proj_dir = root / proj.value 
            
            src_dir = proj_dir / "sources"
            src_dir.mkdir(parents=True, exist_ok=True)
            
            obf_dir = proj_dir / "obfuscated"
            
            for obfu in Obfuscator:
                obfu_dir = obf_dir / obfu.value
                
                if obfu.value == 'tigress':
                    for ob_pass in ObPass:
                        ob_pass_dir = obfu_dir / ob_pass.value
                        ob_pass_dir.mkdir(parents=True, exist_ok=True)
                elif obfu.value == 'ollvm':
                    for ob_pass in OLLVM_PASS:
                        ob_pass_dir = obfu_dir / ob_pass.value
                        ob_pass_dir.mkdir(parents=True, exist_ok=True)


    def download_plain(self, project: Project) -> None:
        # TODO: BARRE PROGRESSION
        # TODO: raise si quelconque exception

        with open(self.json_links, 'r') as out:
            json_data = json.load(out)
            
        project_sources = json_data[project.value]['source']
        link = project_sources['link']
        hash_value = project_sources['hash']
        size = project_sources['size']
        
        r = requests.get(link)
        data_path = Path(self.root_path) / project.value / 'data.zip'
        open(data_path, 'wb').write(r.content)
        
        download_hash = hashlib.md5(data_path.open(mode='rb').read()).hexdigest()
        if hash_value != download_hash: #Make sure the dowload was correct
            logging.exception('The hash of the downloaded file is not the same as the registered one. Please try again')
            exit()
            
        with ZipFile(data_path, 'r') as out:
            out.extractall(path = data_path.parents[0] / "sources")
        data_path.unlink()
        


    def download_obfuscated(self, project: Project, obfuscator: Obfuscator, obfpass: ObPass) -> None:
        # TODO: BARRE PROGRESSION
        # TODO: raise si quelconque exception

        with open(self.json_links, 'r') as out:
            json_data = json.load(out)
            
        project_obfuscated = json_data[project.value]['obfuscated'][obfuscator][obfpass]
        link = project_sources['link']
        hash_value = project_sources['hash']
        size = project_sources['size']
        
        r = requests.get(link)
        data_path = Path(self.root_path) / project.value / 'data.zip'
        open(data_path, 'wb').write(r.content)
        
        download_hash = hashlib.md5(data_path.open(mode='rb').read()).hexdigest()
        if hash_value != download_hash: #Make sure the dowload was correct
            logging.exception('The hash of the downloaded file is not the same as the registered one. Please try again')
            exit()
            
        output_dir = data_path.parents[0] / "obfuscated" / obfuscator.value / obfpass.value
        with ZipFile(data_path, 'r') as out:
            out.extractall(path = output_dir)
        data_path.unlink()
        
       
    def download_all(self) -> None:
        # TODO: BARRE PROGRESSION
        for proj in Project:
            self.download_plain(proj)
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

