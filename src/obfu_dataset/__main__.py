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
from obfu_dataset import get_download_link
from obfu_dataset.types import Project, Obfuscator, ObPass, OptimLevel, Architecture, Compiler
from obfu_dataset.dataset import ObfuDataset
from obfu_dataset.obfuscators.ollvm import OLLVM_PASS
from obfu_dataset.obfuscators.tigress import TIGRESS_PASS


PROJ_OPT = [x.value for x in Project]
OBF_OPT = [x.value for x in Obfuscator]
PASS_OPT = [x.value for x in ObPass]

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
                         typ: BinaryType,
                         project: Project,
                         obfuscator: Obfuscator | None):#, path: str) -> None:
    """Copy data from a url to a local file."""
    # progress.console.log(f"Processing task[{task_id}]: {project.value}")

    package = get_download_link(project, BinaryType.PLAIN)
    # print(package.size, type(package.size))
    # progress.update(task_id, total=package.size, visible=True)

    try:
        response = urlopen(package.link)
    except URLError as e:
        progress.console.log(f":cross_mark: {project.value} failed: {str(e)}")
        return

    # Use effective size except than one provided in links.json
    size = int(response.info()["Content-length"])

    task_id = progress.add_task("download",
                                filename=f"{project.value}",
                                start=True,
                                visible=True,
                                total=size)


    filepath = Path(tempfile.gettempdir()) / package.link.split("/")[-1]
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
    progress.console.log(f":white_check_mark: {project.value} downloaded in: {filepath}")

    # Check hash
    h = hash.hexdigest()
    if h != package.hash:
        print(package)
        progress.console.log(f":cross_mark: {filepath.name} invalid hash: {h} (expected: {package.hash})")
        return

    # Send the zip to the dataset for extraction
    if typ == BinaryType.PLAIN:
        res = dataset.add_source_zip(project, filepath)
    else:
        res = dataset.add_obfuscated_zip(project, obfuscator, filepath)

    if not res:
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
        packages = [(get_download_link(x, BinaryType.PLAIN), x, None) for x in projects]
    else:
        packages = []
        for project in projects:
            for obfuscator in obfuscators:
                for opass in obpasses:
                    packages.append((get_download_link(project, BinaryType.OBFUSCATED, obfuscator, opass), project, obfuscator))

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
    exp_size = sum(x[0].size for x in packages)
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
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for package, proj, obfu in packages:
                # copy_url(progress, task_id, project)
                pool.submit(download_one_package, progress, dataset, type, proj, obfu)
            # progress.console.log("all tasks submitted !")



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


@main.command(name="create")
@click.option('-r', "--root", type=click.Path(), required=True, help='Dataset root directory')
@click.option('-ida_s', "--ida_script", type=click.Path(), required=True, help='IDA script for extracting candidate functions to obfuscation')
def create(root, ida_script):
    #Check if Tigress is available
    if (not 'TIGRESS_HOME' in os.environ) and (shutil.which('tigress') is None):
        logging.ERROR('Tigress does not seem to be installed on your system. Please install it or register the TIGRESS_HOME environment variable.')
        exit()

    dataset = ObfuDataset(root)
    
    #Tigress source generation
    for proj in Project:
        src_dir = Path(dataset.root_path) / (proj.value + "/sources/")
        if not src_dir.exists():
            dataset.download_plain(proj)
        src_candidate = [f for f in src_dir.iterdir() if f.suffix == '.c']
        assert len(src_candidate) == 1
        src_file = src_candidate[0]
        for obf in ObPass:
            obf_path = Path(dataset.root_path) / proj.value / "obfuscated" / "tigress" / obf.value
            for obf_level in range(10, 101, 10):
                level_path = obf_path / str(obf_level)
                level_path.mkdir(parents=True, exist_ok=True)
                for seed in range(1, SEED_NUMBER+1):
                    output_path = level_path / (proj.value + '_tigress_gcc_x64_' + obf.value + '_' + str(obf_level) + '_' + str(seed) + '.c')
                    print('output path:', output_path)
                    match obf.value:
                        case "copy":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Copy', '--Functions=%'+str(obf_level), '--out='+str(output_path), str(src_file)]
                        
                        case "merge":
                            cmd = get_merge_command(dataset.root_path, proj.value, obf_level, seed, ida_script, output_path)
                        case "split":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Split', '--Functions=%'+str(obf_level), '--SplitKinds=deep,block,top', '--SplitCount='+str(SPLIT_COUNT), '--out='+str(output_path), str(src_file)]
                           
                        case "CFF":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Flatten', '--Functions=%'+str(obf_level), '--out='+str(output_path), str(src_file)]
                            
                        case "opaque":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=InitOpaque', '--Functions=main', '--Transform=AddOpaque', '--Functions=%'+str(obf_level), '--out='+str(output_path), str(src_file)]
                            
                        case "virtualize":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Virtualize', '--Functions=%'+str(obf_level), '--out='+str(output_path), str(src_file)]
                            
                        case "encodearith":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=EncodeArithmetic', '--Functions=%'+str(obf_level), '--out='+str(output_path), str(src_file)]
                            
                        case "encodeliteral":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=EncodeLiterals', '--Functions=%'+str(obf_level), '--out='+str(output_path), str(src_file)]
                            
                        case "mix-1":
                            cmd = get_mix1_command(dataset.root_path, proj.value, obf_level, seed, ida_script,
                                                   output_path)

                        case "mix-2":
                            cmd = get_mix2_command(dataset.root_path, proj.value, obf_level, seed, ida_script,
                                                   output_path)


                    #Refine cmd with specific Tigress keywords if necessary
                    if proj.value == 'minilua':
                        additional_keywords = ['-D', '_Float128=double']
                        cmd = cmd[0] + additional_keywords + cmd[1:]
                    if proj.value == 'sqlite':
                        additional_keywords = ['-D', '_Float64=double', '-D', '_Float128=double', '-D', '_Float32x=double', '-D', '_Float64x=double']
                        cmd = cmd[0] + additional_keywords + cmd[1:]
                    print('cmd:', cmd)
                    #p = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                    #output, err = p.communicate()
                    #rc = p.returncode
                    #logging.info('Tigress file:', output_path, 'was generated with return code:', rc)

                            
    #OLLVM source generation
    for proj in Project:
        src_dir = dataset.root / proj.value / "sources"
        src_file = [f for f in src_dir.iterdir() if f.suffix == '.c'][0]
        for obf in ObPass:
            #Assert the pass is available for OLLVM
            if obf in OLLVM_PASS:
                obf_path = Path(dataset.root_path) / proj.value / "obfuscated" / "ollvm" / obf.value 
                for obf_level in range(10, 101, 10):
                    level_path = obf_path / str(obf_level)
                    level_path.mkdir(parent=True)
                    for seed in range(1, SEED_NUMBER+1):
                        for optim in OptimLevel: 
                            obfuscated_file = gen_ollvm_obfuscated(proj, obf, obf_level, seed, ida_script)
                            logging.info('OLLVM file was generated at location:', obfuscated_file)

@main.command(name="compile")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option('-ollvm', type=click.Path(), required=True, help='Path to OLLVM')
def compile(root, ollvm_dir):
    # Tigress
    # 1) Apply a fixup for Tigress .c files that do not compile when necessary 
    # 2) Compile
    for proj in Project:
        tigress_path = Path(root) / "tigress"
        all_binaries = Path(tigress_path).glob("*")
        for file in all_binaries:
            file = tigress_fixup(file)
            for optim in OptimLevel:
                output_bin = file.rename('.c', '') + '_' + optim.value + '.exe'
                match proj.value:
                    case "zlib" | "lz4" | "freetype" | "sqlite":
                        cmd = ['gcc', optim.value, '-D', '__DATE__="1970-01-01"', '-D' '__TIME__="00:00:00"', '-D',  '__TIMESTAMP__="1970-01-01 00:00:00"', '-frandom-seed=123', '-fno-guess-branch-probability', '-o', output_bin]
                    case "minilua":
                        cmd = ['gcc', optim.value, '-D', '__DATE__="1970-01-01"', '-D', '__TIME__="00:00:00"', '-D', '__TIMESTAMP__="1970-01-01 00:00:00"', '-frandom-seed=123', '-fno-guess-branch-probability', '-o', output_bin, '-lm']
                p = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                output, err = p.communicate()
                rc = p.returncode
                logging.info('Tigress file:', file, 'was compiled with return code:', rc)
            
    #OLLVM
    use_ollvm14 = False
    if 'bruno' in ollvm_dir: #TODO
        use_ollvm14 = True
    
    for proj in Project:
        ollvm_path = Path(root) / "ollvm"
        all_binaries = Path(ollvm_path).glob('*')
        for file in all_binaries:
            for optim in OptimLevel:
                output_bin = file.rename('.c', '') + '_' + optim.value + '.exe'
                if use_ollvm14:
                    match proj.value:
                        case "zlib" | "lz4" | "freetype" | "sqlite":
                            cmd = [ollvm_dir + '_build/bin/clang', optim.value, '-D', '__DATE__="1970-01-01"', '-D', '__TIME__="00:00:00"', '-D', '__TIMESTAMP__="1970-01-01 00:00:00"', '-frandom-seed=123', '-o', output_bin, file, '-fpass-plugin=' + ollvm_dir + '_build/lib/Ollvm.so', '-Xclang', '-load', '-Xclang', ollvm_dir + '_build/lib/Ollvm.so']
                            
                        case "minilua":
                            cmd = [ollvm_dir + '_build/bin/clang', optim.value, '-lm', '-D', '__DATE__="1970-01-01"', '-D', '__TIME__="00:00:00"', '-D', '__TIMESTAMP__="1970-01-01 00:00:00"', '-frandom-seed=123', '-o', output_bin, file, '-fpass-plugin=' + ollvm_dir + '_build/lib/Ollvm.so', '-Xclang', '-load', '-Xclang', ollvm_dir + '_build/lib/Ollvm.so']
                            
                else:
                    match proj.value:
                        case "zlib" | "lz4" | "freetype" | "sqlite":
                            cmd = [ollvm_dir + '/build/bin/clang', file, '-o', output_bin] #Because there are pragma directly inside file, no need to call -mllvm
                        case "minilua":
                            cmd = [ollvm_dir + '/build/bin/clang', file, '-o', output_bin, '-lm'] #Because there are pragma directly inside file, no need to call -mllvm
                            
                p = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                output, err = p.communicate()
                rc = p.returncode
                logging.info('OLLVM file:', file, 'was compiled with return code:', rc)
        
@main.command(name="extract-symbols")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option('-s', "--script", type=click.Path(), required=True, help="Script to extract symbols")
@click.option('-ida', "--ida_path", type=click.Path(), required=True, help="IDA path")
def extract_symbols(root, s, ida):
    logging.info('Extracting of symbols will start')
    all_binaries = Path(root).glob("*")
    for (retcode, file) in MultiIDA.map(all_binaries, s, []):
        logging.info('Extraction for file:', file, 'ended with return code:', retcode)

@main.command(name="strip")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
def strip(root):
    logging.info('Stripping will start')
    files = Path(root).glob("*")
    for filename in files:
        cmd = ['strip', filename]
        p = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = p.communicate()
        rc = p.returncode
        logging.info('File:', filename, 'has been stripped with return code:', rc)

@main.command(name="export")
def export():
    # Export both with Quokka & Binexport
    pass



if __name__ == "__main__":
    main()
