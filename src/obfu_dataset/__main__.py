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
from urllib.error import URLError
import signal
import hashlib
import tempfile
import sys
import lief
import json
from joblib import delayed, Parallel
import binexport
import quokka

# third-party libraries
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
from obfu_dataset import get_download_link, DownloadLink, Sample, AVAILABLE_LEVELS
from obfu_dataset.types import Project, Obfuscator, ObPass, OptimLevel, Compiler
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
    """
    Plot the current state of the dataset.
    
    :param root: Dataset root
    :return:
    """
    
    console = Console()
    dataset = ObfuDataset(root)

    available_passes = {
        Obfuscator.TIGRESS: TIGRESS_PASS,
        Obfuscator.OLLVM: OLLVM_PASS
    }

    emoji = lambda x: ":white_check_mark:" if x else (":cross_mark:" if bool(x) == 0 else "~")

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

            # items = [emoji(bool(list(dataset.get_obfu_path(x, obfuscator, obpass).iterdir()))) for x in Project]

            items = []
            for proj in Project:
                alls = []
                for level in AVAILABLE_LEVELS:
                    alls.append(bool(list(dataset.get_obfu_path(proj, obfuscator, obpass, level).iterdir())))
                if all(alls):
                    items.append(emoji(1))
                elif any(alls):
                    items.append(emoji(-1))
                else:
                    items.append(emoji(0))

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
            package.level,
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
                   obpass: list[ObPass],
                   levels: list[int]):

    projects = list(Project) if not projects else projects
    obfuscators = list(Obfuscator) if not obfuscators else obfuscators
    obpasses = list(ObPass) if not obpass else obpass
    levels = list(AVAILABLE_LEVELS) if not levels else levels

    # Get the list of all packages to download
    if type == BinaryType.PLAIN:
        packages = [get_download_link(x, BinaryType.PLAIN) for x in projects]
    else:
        packages = []
        for project in projects:
            for obfuscator in obfuscators:
                for opass in (x for x in obpasses if x in OBFU_PASSES[obfuscator]):
                    for level in levels:
                        packages.append(get_download_link(project, BinaryType.OBFUSCATED, obfuscator, opass, level))

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
    """
    Download only plain (unobfuscated) zip files
    
    :param root: Dataset root
    :param threads: Number of threads to use
    :param project: Optional project to specify
    :return:
    """
    if project:
        projects = [Project(x) for x in project]
    else:  # Take all projects
        projects = [x for x in Project]

    download_packages(root, threads, BinaryType.PLAIN, projects, [], [], [])


@main.command(name="download-obfuscated")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=True, help="Project to download")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option("-op", "--obf-pass", type=click.Choice(PASS_OPT), default=None, required=False, help="Obfuscation pass to download (all if none)")
@click.option("-l", "--level", type=click.Choice([str(l) for l in AVAILABLE_LEVELS]), default=None, required=False, help="Obfuscation levels to download")
def download_obfuscated(root: str, threads: int, project: str, obfuscator: str | None, obf_pass: str | None, level: str | None):
    """
    Download only obfuscated zip files
    
    :param root: Dataset root
    :param threads: Number of threads to use
    :param project: Optional project to specify
    :param obfuscator: Optional obfuscator to specify
    :param obf_pass: Optional obfuscation pass to specify
    :param level: Optional obfuscation level to download
    :return:
    """

    project = [Project(project)]
    obfuscator = [Obfuscator(obfuscator)] if obfuscator else list(Obfuscator)
    obf_pass = [ObPass(obf_pass)] if obf_pass else list(ObPass)
    levels = [int(level)] if level else AVAILABLE_LEVELS

    download_packages(root, threads, BinaryType.OBFUSCATED, project, obfuscator, obf_pass, levels)


@main.command(name="download-all")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
def download_all(root: str, threads: int):
    """
    Download all the dataset
    
    :param root: Dataset root
    :param threads: Number of threads to use
    :return:
    """
    download_packages(root, threads, BinaryType.PLAIN, [], [], [], [])
    download_packages(root, threads, BinaryType.OBFUSCATED, [], [], [], [])


def create_one_obfuscated(dataset: ObfuDataset, console: Console, obfu_sample: Sample) -> bool:
    sample = dataset.get_plain_sample(obfu_sample.project)

    if not sample.source_file.exists():
        console.print(sample.project.value + " sources have to be downloaded first")
        return False

    obfu_sample.base_dir.mkdir(parents=True, exist_ok=True)
    res = True
    out_path = obfu_sample.source_file

    if out_path.exists():
        console.print(f"{out_path} already exists")
        return True

    match obfu_sample.obfuscator:
        case Obfuscator.TIGRESS:
            match obfu_sample.obfpass:
                case ObPass.MERGE:
                    params = get_merge_parameters(sample, obfu_sample.level)
                case ObPass.CFF_ENCODEARITH_OPAQUE:
                    params = get_mix1_parameters(sample, obfu_sample.level, obfu_sample.seed)
                case ObPass.CFF_ENCODEARITH_OPAQUE_SPLIT:
                    params = get_mix2_parameters(sample, obfu_sample.level, obfu_sample.seed, SPLIT_COUNT)
                case _:
                    params = []

            res = run_tigress(sample.source_file, out_path, obfu_sample.seed, obfu_sample.obfpass, params, obfu_sample.level, split_count=SPLIT_COUNT)
            if res:
                console.print(f"Tigress file generated: {out_path}")
                if res := tigress_fixup(obfu_sample.project, out_path):
                    console.print(f"Tigress fixup: {out_path} [OK]")
                else:
                    console.print(f"Tigress fixup: {out_path} [KO]")
            else:
                console.print(f"Tigress execution failed for {out_path}")
                    
        case Obfuscator.OLLVM:
            if res := gen_ollvm_annotated_source(out_path, sample, obfu_sample.obfpass, obfu_sample.level, obfu_sample.seed):
                logging.info(f"OLLVM file was generated at location:{out_path}")
            else:
                logging.warning(f"OLLVM fail to generate: {out_path}")

    return res


@main.command(name="create")
@click.option('-r', "--root", type=click.Path(), required=True, help='Dataset root directory')
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=False, default=None, help="Project to download")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
def create(root: str, project: str, obfuscator: str, threads: int):
    """
    Recreate the source files for the dataset
    
    :param root: Dataset root
    :param project: Optional project to specify
    :param obfuscator: Optional obfuscator to specify
    :param threads: Number of threads to use
    :return:
    """
    
    console = Console()

    if not check_tigress_environ():
        console.print("Tigress does not seem to be installed on your system.\n"
                      "Please install it or register the TIGRESS_HOME environment variable.")
        sys.exit(1)

    console.print(f"Be careful, files located in will be overriden: {root}")
    res = input("continue (Y/N)?: ")
    if res not in ['Y', 'y', 'Yes', 'yes', 'YES']:
        sys.exit(1)

    dataset = ObfuDataset(root)
    
    projects = [Project(project)] if project else list(Project)
    obfuscators = [Obfuscator(obfuscator)] if obfuscator else list(Obfuscator)

    # Create all configurations to generate
    configs = list(dataset.iter_obfuscated_samples(projects=projects, obfuscators=obfuscators))

    Parallel(n_jobs=threads, backend='threading')(delayed(create_one_obfuscated)(dataset, console, sample) for sample in configs)


def compile_binary(console: Console, dataset: ObfuDataset, sample: Sample, override: bool):
    if sample.binary_file.exists() and not override:
        console.log(f":check_mark: {sample.binary_file} already compiled")
    else:
        console.log(f"compile sample: {sample.binary_file.name}")
        if dataset.compile(sample):
            console.log(f":white_check_mark: {sample.binary_file} compiled")
        else:
            console.log(f":cross_mark: {sample.binary_file} fail to compile")


@main.command(name="compile")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=False, default=None, help="Project to download")
@click.option("-v", "--variant", type=click.Choice(BINT_OPT), required=True, help="Binary variant to compile")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option("-c", "--compiler", type=click.Choice(COMPILER_OPT), default=None, required=False, help="Compiler to use")
@click.option("--optim", type=click.Choice(OPTIM_OPT), default=None, required=False, help="Optimization level")
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
@click.option('--override', type=int, is_flag=True, default=False, help="Override existing binaries")
def compile(root: str, project: str, variant: str, obfuscator: str, compiler: str, optim: str, threads: int, override: bool):
    """
    Once the obfuscated sources are created, compile both plain and obfuscated binaries. OLLVM path and additional parameters should be given
    through environment variables:
    * OLLVM_PATH=/home/foo/_build/bin/
    * OLLVM_ARGS="-fpass-plugin=/home/foo/_build/lib/Ollvm.so -Xclang -load -Xclang /home/foo/_build/lib/Ollvm.so"

    :param root: Dataset root
    :param project: Optional project to specify
    :param variant: Optional mode for compiler, either plain or obfuscated binaries
    :param obfuscator: Optional obfuscator to specify
    :param compiler: Optional compiler to specify
    :param optim: Optional optimization level to specify
    :param threads: Number of threads to use
    :param override: Override existing binary
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
    
    Parallel(n_jobs=threads)(delayed(compile_binary)(console, dataset, sample, override) for sample in samples)


@main.command(name="extract-symbols")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
def extract_symbols(root):
    """
    Once the obfuscated binaries are compiled, extract their symbols as a dictionnary {fun_addr:fun_name}
    
    :param root: Dataset root
    :return:
    """
    console = Console()

    dataset = ObfuDataset(root)
    # User directly download the plain sources with .exe, .json, .BinExport, .Quokka
    # No need to reproduce for plain
    # for sample in dataset.iter_plain_samples(): 
    #    extract(console, sample.binary_file)

    for sample in dataset.iter_obfuscated_samples():
        if (not sample.symbols_file.exists()) and sample.binary_file.exists():

            binary = lief.parse(sample.binary_file)
            gt = {hex(f.address): f.name for f in binary.functions}
            sample.symbols_file.write_text(json.dumps(gt))
            if gt:
                console.log(f":white_check_mark: {sample.symbols_file}")
            else:
                console.log(f":cross_mark: {sample.symbols_file}")



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
    """
    Once the obfuscated symbols are extracted, strip the binaries
    
    :param root: Dataset root
    :return:
    """
    
    console = Console()

    dataset = ObfuDataset(root)
    # User directly download the plain sources with .exe, .json, .BinExport, .Quokka
    # No need to reproduce for plain
    # for sample in dataset.iter_plain_samples():
    #    strip_file(console, sample.binary_file)

    for sample in dataset.iter_obfuscated_samples():
        if sample.binary_file.exists() and sample.symbols_file.exists(): # Strip only when symbols data are already extracted
            strip_file(console, sample.binary_file)


def export_binary(console: Console, sample: Sample, exporter: str) -> True:
    out_file = sample.quokka_file if exporter == "Quokka" else sample.binexport_file
    if out_file.exists():
        console.log(f"Exported file {out_file} already exists")
        return True
    else:
        if exporter == "Quokka":
            binary = quokka.Program.from_binary(str(sample.binary_file), timeout=500000)
        elif exporter == "BinExport":
            binary = binexport.ProgramBinExport.from_binary_file(sample.binary_file, open_export=False)
        else:
            assert False

        if binary:
            console.log(f":white_check_mark: {sample.binary_file}")
            return True
        else:
            console.log(f":cross_mark: {sample.binary_file}")
            return False

    
@main.command(name="export")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option("-e", "--export", type=click.Choice(['BinExport', 'Quokka']), required=False, default=None, help='Export to execute')
@click.option('-t', '--threads', type=int, default=3, help="Number of downloading threads")
def export(root, export, threads):
    """
    Once the binaries are stripped, export them.
    
    :param root: Dataset root
    :param export: Optional export type to specify
    :param threads: Number of threads to use
    :return:
    """
    
    exporter = [export] if export else ['BinExport', 'Quokka']

    console = Console()

    dataset = ObfuDataset(root)
    for e in exporter:
        console.print(f"Start exporting with: {e}")
        Parallel(n_jobs=threads, backend='threading')(delayed(export_binary)(console, sample, e) for sample in dataset.iter_obfuscated_samples())
    

if __name__ == "__main__":
    main()
