import os
import random
import re
from operator import attrgetter
from random import Random
import subprocess

from obfu_dataset import ObPass, Sample
from pathlib import Path
import clang.cindex
import logging
import clang
import pkg_resources

OLLVM_PASS = [
    ObPass.CFF,
    ObPass.OPAQUE,
    ObPass.ENCODEARITH,
    ObPass.CFF_ENCODEARITH_OPAQUE
]

def find_libclang() -> Path | None:
    for file in Path("/lib/x86_64-linux-gnu/").iterdir():
        if re.match(r"libclang-\d+\.so\.?\d*", file.name):
            return file
    return None


def _obpass_to_annotation(obpass):
    match obpass:
        case ObPass.CFF:
            items = ["fla"]
        case ObPass.OPAQUE:
            items = ['bcf']
        case ObPass.ENCODEARITH:
            items = ['sub']
        case ObPass.CFF_ENCODEARITH_OPAQUE:
            items = ["fla", "sub", "bcf"]
        case _:
            assert False
    s = ",".join(f"annotate({x})" for x in items)
    return f"__attribute__(({s}))\n"


def compute_symbols_stats(bin_symbols, funcs):
    # Test intersection of functions and the binary
    # bin_symbols = {x for x in get_symbols(srcfile.with_suffix("")).values()}
    source_symbols = {f.spelling for l in funcs.values() for f in l}
    print("Source but not Binary:\n", source_symbols - bin_symbols)
    print("------------------------------------------")
    print("Binary but not Source:\n", bin_symbols - source_symbols)
    print("------------------------------------------")
    print(f"src: {len(source_symbols)} | bin: {len(bin_symbols)}")


def find_functions(node, out_files):
    """
    Search function nodes and fill `out_files` object
    """
    # Check if the node is a function declaration or definition
    if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
        # Get the location of the function declaration
        file = Path(node.location.file.name)

        # print(file, type(file))
        if file.name in out_files:
            out_files[file.name].append(node)

    # Recurse into child nodes
    for child in node.get_children():
        find_functions(child, out_files)


def gen_ollvm_annotated_source(dst_file: Path, sample: Sample, obpass: ObPass, obf_level: int, seed: int) -> bool:
    symbols: set[str] = set(sample.get_symbols().values())

    # Initialize the Clang index
    libclang = find_libclang()
    if pkg_resources.get_distribution('clang').version != str(libclang).split('.so.')[-1]:
        logging.warning("Your clang python package does not match your system file. Please install clang"+libclang.split('.so.')[-1])
        sys.exit(1)
    if not libclang:
        logging.error("can't find libclang.so")
        return False

    clang.cindex.Config.loaded = False #For an unknown reason, gen_ollvm_annotated_source works the first time it is called, but raises an error at the second time. Need to set it to avoid error (something related to the fact the lib is already loaded).
    clang.cindex.Config.set_library_file(libclang)
    index = clang.cindex.Index.create()

    # Read both files
    cname = sample.source_file.name
    hfile = sample.source_file.with_suffix(".h")
    files = {
        cname: open(sample.source_file, 'r').readlines(),
        hfile.name: open(hfile, "r").readlines()
    }

    # Parse the file with Clang
    translation_unit = index.parse(sample.source_file)

    # Get the AST root node (translation unit) and search for functions
    funcs = {x: [] for x in files}
    find_functions(translation_unit.cursor, funcs)

    # Take .c functions shuffle them to select a subset to obfuscate
    function_list = [x for x in funcs[cname]]
    Random(seed).shuffle(function_list)  # shuffle elements
    candidate_functions = function_list[:int(obf_level / 100 * len(function_list))]

    # Insert annotation in the source file and write it back
    # Iterate function from the end of the file to the beginning so that line numbers wont be shifted by insertion
    annotation_line = _obpass_to_annotation(obpass)
    
    lines = files[cname]

    for fun in sorted(candidate_functions, key=lambda x: x.location.line, reverse=True):
        lines.insert(fun.location.line - 1, annotation_line)

    # Finally write back file
    with open(dst_file, "w") as out:
        out.writelines(lines)

    return True


def compile_ollvm(sample: Sample) -> bool:
    ollvm_path = Path(os.environ['OLLVM_PATH'])
    ollvm_args = os.environ.get("OLLVM_ARGS")
    if ollvm_path.name != "clang":
        ollvm_path = ollvm_path / "clang"

    args = [str(ollvm_path),
            f"-{sample.optimization.value}",
            "-lm",
            "-D", '__DATE__="1970-01-01"',
            '-D', '__TIME__="00:00:00"',
            '-D', '__TIMESTAMP__="1970-01-01 00:00:00"',
            "-frandom-seed=123",
            "-lm",
            "-o", f"{sample.binary_file}",
            f"{sample.source_file}"
    ] + ollvm_args.split(" ")
    
    print('compile:', args)
    p = subprocess.Popen(args, stdin=None, stdout=None, stderr=None)
    output, err = p.communicate()
    return p.returncode == 0
