import click
import os
import shutil
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from threading import Event
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import signal
import hashlib
from subprocess import PIPE
import tempfile
import sys
import lief
import json
from joblib import delayed, Parallel
import binexport
import quokka

# third-party libraries
from idascript import MultiIDA, iter_binary_files, IDA
from rich.logging import RichHandler
from rich.table import Table
from rich.console import Console
from rich.spinner import Spinner
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from obfu_dataset.types import BinaryType
# local imports
from obfu_dataset import get_download_link, DownloadLink
from obfu_dataset.types import Project, Obfuscator, ObPass, OptimLevel, Architecture, Compiler
from obfu_dataset.dataset import ObfuDataset
from obfu_dataset.obfuscators.ollvm import OLLVM_PASS, gen_ollvm_annotated_source
from obfu_dataset.obfuscators.tigress import TIGRESS_PASS, check_tigress_environ, run_tigress, get_merge_parameters, \
                                             get_mix1_parameters, get_mix2_parameters, tigress_fixup

PROJ_OPT = [x.value for x in Project]
OBF_OPT = [x.value for x in Obfuscator]
PASS_OPT = [x.value for x in ObPass]
BINT_OPT = [x.value for x in BinaryType]
COMPILER_OPT = [x.value for x in Compiler]
OPTIM_OPT = [x.value for x in OptimLevel]

OBFU_PASSES = {
    Obfuscator.TIGRESS: TIGRESS_PASS,
    Obfuscator.OLLVM: OLLVM_PASS
}

SEED_NUMBER = 10
SPLIT_COUNT = 2


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(),
        logging.FileHandler("logfile.log")
    ]
)

done_event = Event()

def handle_sigint(signum, frame):
    done_event.set()


signal.signal(signal.SIGINT, handle_sigint)


def convert_size(size: int) -> str:
    """Convert byte size to string"""
    unitees = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']

    taille = float(size)
    indice_unitee = 0
    while taille >= 1024 and indice_unitee < len(unitees) - 1:
        taille /= 1024
        indice_unitee += 1
    return f"{taille:.2f} {unitees[indice_unitee]}"


@click.group(context_settings={'help_option_names': ['-h', '--help']})
def main():
    pass


@main.command(name="ls")
@click.argument("root", type=click.Path(exists=True))
def ls(root: str):
    console = Console()
    dataset = ObfuDataset(root)

    available_passes = {
        Obfuscator.TIGRESS: TIGRESS_PASS,
        Obfuscator.OLLVM: OLLVM_PASS
    }

    emoji = lambda x: ":white_check_mark:" if x else ":cross_mark:"

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Sample")#, style="dim", width=12)
    for project in Project:
        table.add_column(project.value, justify="center")

    # Check sources
    table.add_row(*["sources"]+[emoji(bool(list(dataset.get_src_path(x).iterdir()))) for x in Project])

    longest_obf = max(len(x.value) for x in Obfuscator)
    longest_pass = max(len(x.value) for x in ObPass)

    for obfuscator in Obfuscator:
        oname = obfuscator.value
        for obpass in available_passes[obfuscator]:
            pname = obpass.value
            #items = [emoji(next(dataset.iter_obfuscated_samples([x], [obfuscator], [obpass])).exists) for x in Project]
            items = [emoji(bool(list(dataset.get_obfu_path(x, obfuscator, obpass).iterdir()))) for x in Project]
            first = f"{oname}{' '*(longest_obf-len(oname))}|{pname}{' '*(longest_pass-len(pname))}"
            table.add_row(first, *items)

    console.print(table)


def download_one_package(progress: Progress,
                         dataset: ObfuDataset,
                         package: DownloadLink):#, path: str) -> None:
    """Copy data from a url to a local file."""
    # progress.console.log(f"Processing package: {package}")

    pname = package.project.name
    filepath = Path(tempfile.gettempdir()) / package.link.split("/")[-1]

    if filepath.exists():
        progress.console.log(f"found .zip in cache: {filepath}")

    else:
        # Try to download it
        try:
            response = urlopen(package.link)
        except URLError as e:
            progress.console.log(f":cross_mark: {pname} failed: {str(e)}")
            return

        # Use effective size except than one provided in links.json
        size = int(response.info()["Content-length"])

        task_id = progress.add_task("download",
                                    filename=f"{pname}",
                                    start=True,
                                    visible=True,
                                    total=size)

        hash = hashlib.md5()

        with open(filepath, "wb") as dest_file:
            # progress.start_task(task_id)
            for data in iter(partial(response.read, 32768), b""):
                hash.update(data)
                dest_file.write(data)
                progress.update(task_id, advance=len(data))
                if done_event.is_set():
                    return

        # When download finished
        progress.remove_task(task_id)
        progress.console.log(f":white_check_mark: {pname} downloaded in temporary dir: {filepath}")

        # Check hash
        h = hash.hexdigest()
        if h != package.hash:
            print(package.link)
            progress.console.log(f":cross_mark: {filepath.name} invalid hash: {h} (expected: {package.hash})")


    # Send the zip to the dataset for extraction
    if package.type == BinaryType.PLAIN:
        res = dataset.add_source_zip(package.project, filepath)
    else:
        res = dataset.add_obfuscated_zip(
            package.project,
            package.obfuscator,
            package.obpass,
            filepath)

    if res:
        progress.console.log(f":white_check_mark: {filepath.name} extracted in: {res}")
    else:
        progress.console.log(f":cross_mark: {filepath.name} zip extraction failed")

    # in either case remove file
    filepath.unlink()



def download_packages(root: str,
                   threads: int,
                   type: BinaryType,
                   projects: list[Project],
                   obfuscators: list[Obfuscator],
                   obpass: list[ObPass]):

    projects = list(Project) if not projects else projects
    obfuscators = list(Obfuscator) if not obfuscators else obfuscators
    obpasses = list(ObPass) if not obpass else obpass

    # Get the list of all packages to download
    if type == BinaryType.PLAIN:
        packages = [get_download_link(x, BinaryType.PLAIN) for x in projects]
    else:
        packages = []
        for project in projects:
            for obfuscator in obfuscators:
                for opass in (x for x in obpasses if x in OBFU_PASSES[obfuscator]):
                    packages.append(get_download_link(project, BinaryType.OBFUSCATED, obfuscator, opass))

    # Instanciate a progress bar
    progress = Progress(
        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
    )

    # Check disk availability
    exp_size = sum(x.size for x in packages)
    info = shutil.disk_usage(root)
    ppe, ppi = convert_size(exp_size), convert_size(info.free)
    if exp_size > info.free:
        progress.console.log(f":cross_mark: insufficient disk space: expected to "
                             f"download {ppe}, available: {ppi}")
    else:
        progress.console.log(f"about to download {ppe}"
                             f" available {ppi} (on {convert_size(info.total)})")

    # Instantiate dataset object
    dataset = ObfuDataset(root)

    with progress:
        if threads > 1:
            with ThreadPoolExecutor(max_workers=threads) as pool:
                for package in packages:
                    pool.submit(download_one_package, progress, dataset, package)
        else:
            for package in packages:
                download_one_package(progress, dataset, package)



@main.command(name="download-plain")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
@click.argument("project", required=False, type=click.Choice(PROJ_OPT), nargs=-1)
def download_plain(root: str, threads: int, project: tuple[str]):

    if project:
        projects = [Project(x) for x in project]
    else:  # Take all projects
        projects = [x for x in Project]

    download_packages(root, threads, BinaryType.PLAIN, projects, [], [])


@main.command(name="download-obfuscated")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=True, help="Project to download")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option("-op", "--obf-pass", type=click.Choice(PASS_OPT), default=None, required=False, help="Obfuscation pass to download (all if none)")
def download_obfuscated(root: str, threads: int, project: str, obfuscator: str | None, obf_pass: str | None):

    project = [Project(project)]
    obfuscator = [Obfuscator(obfuscator)] if obfuscator else list(Obfuscator)
    obf_pass = [ObPass(obf_pass)] if obf_pass else list(ObPass)

    download_packages(root, threads, BinaryType.OBFUSCATED, project, obfuscator, obf_pass)


@main.command(name="download-all")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
def download_all(root: str, threads: int):
    download_packages(root, threads, BinaryType.PLAIN, [], [], [])
    download_packages(root, threads, BinaryType.OBFUSCATED, [], [], [])


def create_binary(dataset, console, proj, obfuscator, obf, level, seed):
    sample = dataset.get_plain_sample(proj)
    src_file = dataset.get_src_path(proj) / (proj.value + ".c")
    if not src_file.exists():
        console.print(proj.value + " sources have to be downloaded first")
        sys.exit(1)
    level_path = dataset.get_obfu_path(proj, obfuscator, obf) / str(level)
    level_path.mkdir(parents=True, exist_ok=True)
    match obfuscator:
        case Obfuscator.TIGRESS:
            match obf:
                case ObPass.MERGE:
                    params = get_merge_parameters(sample, level)
                case ObPass.CFF_ENCODEARITH_OPAQUE:
                    params = get_mix1_parameters(sample, level, seed)
                case ObPass.CFF_ENCODEARITH_OPAQUE_SPLIT:
                    params = get_mix2_parameters(sample, level, seed, SPLIT_COUNT)
                case _:
                    params = []
        
            output_path = level_path / f"{proj.value}_{Obfuscator.TIGRESS.value}_gcc_x64_{obf.value}_{level}_{str(seed)}.c"
            if not output_path.exists():
                res = run_tigress(src_file, output_path, seed, obf, params, level, split_count=SPLIT_COUNT)
                if res:
                    console.print(f"Tigress file generated: {output_path}")
                else:
                    console.print(f"Tigress execution failed for {output_path}")
                if tigress_fixup(proj, output_path):
                    console.print(f"Tigress fixup: {output_path} [OK]")
                else:
                    console.print(f"Tigress fixup: {output_path} [KO]")
                    
        case Obfuscator.OLLVM:      
            level_path = dataset.get_obfu_path(proj, Obfuscator.OLLVM, obf) / str(level)
            level_path.mkdir(parents=True, exist_ok=True)
            output_file = level_path / f"{proj.value}_{Obfuscator.OLLVM.value}_clang14_x64_{obf.value}_{level}_{str(seed)}.c"
            if not output_file.exists():
                if gen_ollvm_annotated_source(output_file, sample, obf, level, seed):
                    logging.info(f"OLLVM file was generated at location:{output_file}")
                else:
                    logging.warning(f"OLLVM fail to generate: {output_file}")


@main.command(name="create")
@click.option('-r', "--root", type=click.Path(), required=True, help='Dataset root directory')
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=False, default=None, help="Project to download")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
def create(root: str, project:str, obfuscator:str, threads:int):
    console = Console()

    if not check_tigress_environ():
        console.print("Tigress does not seem to be installed on your system.\n"
                      "Please install it or register the TIGRESS_HOME environment variable.")
        sys.exit(1)

    dataset = ObfuDataset(root)
    
    projects = [Project(project)] if project else list(Project)
    obfuscators = [Obfuscator(obfuscator)] if obfuscator else list(Obfuscator)
    parameters = [(p, obfu, ob, l, s) for p in projects for obfu in obfuscators for ob in TIGRESS_PASS for l in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100] for s in range(1, 11) if obfu.value == 'tigress'] + [(p, obfu, ob, l, s) for p in projects for obfu in obfuscators for ob in OLLVM_PASS for l in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100] for s in range(1, 11) if obfu.value == 'ollvm']
    Parallel(n_jobs=threads, backend='threading')(delayed(create_binary)(dataset, console, p, obfu, ob, l, s) for (p, obfu, ob, l, s) in parameters)#TODO
    exit()
    
    for proj in projects:
        sample = dataset.get_plain_sample(proj)
        src_file = dataset.get_src_path(proj) / (proj.value + ".c")
        if not src_file.exists():
            console.print(proj.value + " sources have to be downloaded first")
            continue
            
        #Tigress source generation
        if Obfuscator.TIGRESS in obfuscators:
            for obf in TIGRESS_PASS:
                obf_path = dataset.get_obfu_path(proj, Obfuscator.TIGRESS, obf)

                for obf_level in range(10, 101, 10):
                    level_path = obf_path / str(obf_level)
                    level_path.mkdir(parents=True, exist_ok=True)
                    for seed in range(1, SEED_NUMBER+1):
                        match obf:
                            case ObPass.MERGE:
                                params = get_merge_parameters(sample, obf_level)
                            case ObPass.CFF_ENCODEARITH_OPAQUE:
                                params = get_mix1_parameters(sample, obf_level, seed)
                            case ObPass.CFF_ENCODEARITH_OPAQUE_SPLIT:
                                params = get_mix2_parameters(sample, obf_level, seed, SPLIT_COUNT)
                            case _:
                                params = []
                        
                        output_path = level_path / f"{proj.value}_{Obfuscator.TIGRESS.value}_gcc_x64_{obf.value}_{obf_level}_{str(seed)}.c"
                        if not output_path.exists():
                            res = run_tigress(src_file, output_path, seed, obf, params, obf_level, split_count=SPLIT_COUNT)
                            if res:
                                console.print(f"Tigress file generated: {output_path}")
                            else:
                                console.print(f"Tigress execution failed for {output_path}")
                            if tigress_fixup(proj, output_path):
                                console.print(f"Tigress fixup: {output_path} [OK]")
                            else:
                                console.print(f"Tigress fixup: {output_path} [KO]")
                                
        #OLLVM source generation
        if Obfuscator.OLLVM in obfuscators:                    
            for obf in OLLVM_PASS:
                obf_path = dataset.get_obfu_path(proj, Obfuscator.OLLVM, obf)
                for obf_level in range(10, 101, 10):
                    level_path = obf_path / str(obf_level)
                    level_path.mkdir(parents=True, exist_ok=True)
                    for seed in range(1, SEED_NUMBER+1):
                        output_file = level_path / f"{proj.value}_{Obfuscator.OLLVM.value}_clang14_x64_{obf.value}_{obf_level}_{str(seed)}.c"
                        if not output_file.exists():
                            if gen_ollvm_annotated_source(output_file, sample, obf, obf_level, seed):
                                logging.info(f"OLLVM file was generated at location:{output_file}")
                            else:
                                logging.warning(f"OLLVM fail to generate: {output_file}")


def compile_binary(console, sample):
    if (not sample.binary_file.exists()) and (sample.source_file.exists()):
        print(f"compile sample: {sample.binary_file.name}")
        if dataset.compile(sample):
            console.log(f":white_check_mark: {sample.binary_file} compiled")
        else:
            console.log(f":cross_mark: {sample.binary_file} fail to compile")
            exit()

@main.command(name="compile")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=False, default=None, help="Project to download")
@click.option("-v", "--variant", type=click.Choice(BINT_OPT), required=True, help="Binary variant to compile")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option("-c", "--compiler", type=click.Choice(COMPILER_OPT), default=None, required=False, help="Compiler to use")
@click.option("--optim", type=click.Choice(OPTIM_OPT), default=None, required=False, help="Optimization level")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
def compile(root: str, project: str, variant: str, obfuscator: str, compiler: str, optim: str, threads: int):
    """
    Compile both plain and obfuscated binaries. OLLVM path and additional parameters should be given
    through environment variables:
    * OLLVM_PATH=/home/foo/_build/bin/
    * OLLVM_ARGS="-fpass-plugin=/home/foo/_build/lib/Ollvm.so -Xclang -load -Xclang /home/foo/_build/lib/Ollvm.so"

    :param root: Dataset root
    :param ollvm_dir: directory where OLLVM is located
    :return:
    """
    console = Console()

    projects = [Project(project)] if project else list(Project)
    obfuscators = [Obfuscator(obfuscator)] if obfuscator else list(Obfuscator)
    compilers = [Compiler(compiler)] if compiler else list(Compiler)
    optims = [OptimLevel(optim)] if optim else list(OptimLevel)

    if Obfuscator.OLLVM in obfuscators:
        if "OLLVM_PATH" not in os.environ:
            print("OLLVM_PATH environment variable should be provided to compile with OLLVM")
            sys.exit(1)

    dataset = ObfuDataset(root)

    # Get the list of samples to compile
    typ = BinaryType(variant)
    if typ == BinaryType.PLAIN:
        samples = list(dataset.iter_plain_samples(projects, compilers, optims))
    elif typ == BinaryType.OBFUSCATED:
        samples = list(dataset.iter_obfuscated_samples(projects, obfuscators, compilers=compilers, optims=optims))
    else:
        assert False
    
    Parallel(n_jobs=threads)(delayed(compile_binary)(console, sample) in samples)

def extract(console, binary_file):
    binary = lief.parse(binary_file)
    gt = {hex(f.address):f.name for f in binary.functions}
    binary_file.with_suffix('.json').write_text(json.dumps(gt))
    if gt:
        console.log(f":white_check_mark: {binary_file.with_suffix('.json')}")
    else:
        console.log(f":cross_mark: {binary_file.with_suffix('.json')}")

@main.command(name="extract-symbols")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
def extract_symbols(root):
    console = Console()

    dataset = ObfuDataset(root)
    # User directly download the plain sources with .exe, .json, .BinExport, .Quokka
    # No need to reproduce for plain
    # for sample in dataset.iter_plain_samples(): 
    #    extract(console, sample.binary_file)

    for sample in dataset.iter_obfuscated_samples():
        if (not sample.symbols_file.exists()) and sample.binary_file.exists():
            extract(console, sample.binary_file)


def strip_file(console: Console, file: Path) -> None:
    p = subprocess.Popen(['strip', str(file)], stdin=None, stdout=None, stderr=None)
    _, _ = p.communicate()
    if p.returncode == 0:
        console.log(f":white_check_mark: {file}")
    else:
        console.log(f":cross_mark: {file}")


@main.command(name="strip")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
def strip(root):
    console = Console()

    dataset = ObfuDataset(root)
    # User directly download the plain sources with .exe, .json, .BinExport, .Quokka
    # No need to reproduce for plain
    # for sample in dataset.iter_plain_samples():
    #    strip_file(console, sample.binary_file)

    for sample in dataset.iter_obfuscated_samples():
        if sample.binary_file.exists():
            strip_file(console, sample.binary_file)


def export_binary(console: Console, file: Path, export: str) -> None:
    if (not file.quokka_file.exists()) and export == 'Quokka':
        binary = quokka.Program.from_binary(str(file.binary_file), timeout=500000)  #Add a very large timeout for large binaries
        if isinstance(binary, quokka.program.Program):
            console.log(f":white_check_mark: {file.binary_file}")
            file.binary_file.with_suffix(file.binary_file.suffix + '.Quokka').rename(file.binary_file.with_suffix('.Quokka'))
            if file.binary_file.with_suffix(file.binary_file.suffix + '.i64').exists():
                file.binary_file.with_suffix(file.binary_file.suffix + '.i64').unlink()
        else:
            console.log(f":cross_mark: {file.binary_file}")
            
    if (not file.binexport_file.exists()) and export == 'BinExport':
        binary = binexport.ProgramBinExport.from_binary_file(file.binary_file, open_export=False)
        if binary:
            console.log(f":white_check_mark: {file.binary_file}")
        else:
            console.log(f":cross_mark: {file.binary_file}")
    
@main.command(name="export")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option("-e", "--export", type=click.Choice(['BinExport', 'Quokka']), required=False, default=None, help='Export to execute')
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
def export(root, export, threads):
  
    export = [export] if export else ['BinExport', 'Quokka']

    console = Console()

    dataset = ObfuDataset(root)
    for e in export:
        Parallel(n_jobs=threads, backend='threading')(delayed(export_binary)(console, sample, e) for sample in dataset.iter_obfuscated_samples() if sample.symbols_file.exists())
    

if __name__ == "__main__":
    main()
