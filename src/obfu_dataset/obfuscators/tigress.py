import os
import shutil
from pathlib import Path
import subprocess
import json
import re
from random import Random

from obfu_dataset import ObPass, Sample, Project
from obfu_dataset.projects import error_functions_zlib, error_functions_lz4, error_functions_minilua, error_functions_sqlite, FUN_BLACKLIST


TIGRESS_PASS = [
    ObPass.COPY,
    ObPass.MERGE,
    ObPass.SPLIT,
    ObPass.CFF,
    ObPass.OPAQUE,
    ObPass.VIRTUALIZE,
    ObPass.ENCODEARITH,
    ObPass.ENCODELITERAL,
    ObPass.CFF_ENCODEARITH_OPAQUE,
    ObPass.CFF_ENCODEARITH_OPAQUE_SPLIT
]

PASS_CMDLINE = {
    ObPass.COPY: "Copy",
    ObPass.MERGE: "Merge",
    ObPass.SPLIT: "Split",
    ObPass.CFF: "Flatten",
    ObPass.OPAQUE: "AddOpaque",
    ObPass.VIRTUALIZE: "Virtualize",
    ObPass.ENCODEARITH: "EncodeArithmetic",
    ObPass.ENCODELITERAL: "EncodeLiterals",
    ObPass.CFF_ENCODEARITH_OPAQUE: "NC",
    ObPass.CFF_ENCODEARITH_OPAQUE_SPLIT: "NC"
}

def check_tigress_environ() -> bool:
    return 'TIGRESS_HOME' in os.environ and shutil.which('tigress') is not None


def run_tigress(infile: Path,
                outfile: Path,
                seed: int,
                obfu: ObPass,
                params: list[str],
                fun_perc: int,
                split_count: int = -1) -> bool:
    cmd = [
        "tigress",
        "-D", "_Float64=double",
        "-D", "_Float128=double",
        "-D", "_Float32x=double",
        "-D", "_Float64x=double",
        "--Environment=x86_64:Linux:Gcc:4.6",
        f"--Seed={seed}",
        f"--Transform=InitOpaque" if obfu.value == 'opaque' else ""
        f"--Functions=main" if obfu.value == 'opaque' else ""
        f"--Transform={PASS_CMDLINE[obfu]}" if not params else ""] + \
        params + \
        [f"--SplitKinds=deep,block,top" if obfu.value == 'split' else "",
        f"--SplitCount={split_count}" if obfu.value == 'split' else "",
        f"--Functions=%{fun_perc}" if not params else "",
        "--out=" + str(outfile),
        str(infile)
    ]
    while '' in cmd:
        cmd.remove('')
    print('cmd:', cmd)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    return p.returncode == 0


def _fix_source_zlib(lines: list[str]) -> None:
    i = 0
    while i < len(lines):
        line = lines[i]
        #zlib merge
        if re.search(r"configuration_table\[\d+]\.func = & deflate_(stored|slow|fast);", line):
            lines.pop(i)
        #zlib copy
        if 'extern FILE *tmpfile(void)  __attribute__((__malloc__(fclose,1), __malloc__)) ;\n' in line:
            lines.pop(i)
        i=i+1

def _fix_source_lz4(lines: list[str]) -> None:
    i = 0
    while i < len(lines):
        line = lines[i]
        #lz4 merge
        if 'void __attribute__((__visibility__("default")))  merge_dummy_return' in line:
            lines[i] = line.replace('void ', '')
        i+=1

def _fix_source_sqlite(lines: list[str]) -> None:
    i = 0
    while i < len(lines):
        line = lines[i]
        #sqlite virtualize
        if '    *((void __attribute__((__overloaded__))  *)(' in line:
            del lines[i-1:i+1] # remove previous and current one

        #sqlite flatten
        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) open_memstream)(char **__bufloc ,\n'
            in lines[i+1]) and ('size_t *__sizeloc )  __attribute__((__malloc__(fclose,1),\n' in lines[i+2]) and\
                ('__malloc__)) ;\n' in lines[i+3]):
            del lines[i:i+3]

        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__asm__("fopen64") __attribute__((__malloc__(fclose,1),\n' in lines[i+1]) and ('__malloc__)) ;\n'
                                                                                                in lines[i+2]):
            del lines[i:i+2]

        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fopencookie)(void * __restrict  '
            '__magic_cookie ,\n' in lines[i+1]) and ('char const   * __restrict  __modes ,\n' in lines[i+2]) \
                and ('cookie_io_functions_t __io_funcs )  __attribute__((__malloc__(fclose,1),\n' in lines[i+3]) \
                and ('__malloc__)) ;\n' in lines[i+4]):
            del lines[i:i+4]

        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fmemopen)(void *__s ,\n' in lines[i+1]) \
            and ('size_t __len ,\n' in lines[i+2]) and ('char const   *__modes )  __attribute__((__malloc__(fclose,1),\n' in lines[i+3]) \
            and ('__malloc__)) ;\n' in lines[i+4]):
            del lines[i:i+4]

        if 'extern FILE *tmpfile64(void)  __attribute__((__malloc__(fclose,1), __malloc__)) ;\n' in lines[i+1]:
            del lines[i:i+1]

        if ('extern FILE *fopen64(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__attribute__((__malloc__(fclose,1),\n' in lines[i+1]) and ('__malloc__)) ;\n' in lines[i+2]):
            del lines[i:i+2]

        if ('extern  __attribute__((__nothrow__)) void *( __attribute__((__warn_unused_result__,\n' in lines[i+1]) and\
                ('__leaf__)) realloc)(void *__ptr , size_t __size )  __attribute__((__alloc_size__(2))) ;\n' in lines[i+2]):
            del lines[i:i+2]

        if ('extern  __attribute__((__nothrow__)) void *( __attribute__((__warn_unused_result__,\n' in lines[i+1]) and\
                ('__leaf__)) reallocarray)(void *__ptr , size_t __nmemb , size_t __size )  __attribute__((__malloc__(__builtin_free,1),\n' in lines[i+2]) and\
                ('__malloc__(reallocarray,1), __alloc_size__(2,3))) ;\n' in lines[i+3]):
            del lines[i:i+3]

        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fdopen)(int __fd ,\n' in lines[i+1]) \
                and ('char const   *__modes )  __attribute__((__malloc__(fclose,1),\n' in lines[i+2]) \
                and ('__malloc__)) ;\n' in lines[i+3]):
            del lines[i:i+3]
        i+=1
        
def _fix_source_minilua(lines: list[str]) -> None:
    i = 0
    while i < len(lines):
        line = lines[i]
        #minilua virtualize
        if ('__attribute__((__malloc__(fclose,1),\n' in lines[i + 1]) and (lines[i + 2] == '__malloc__)) ;\n'):
            del lines[i:i+2]
        if ('__attribute__((__malloc__(pclose,1),\n' in lines[i + 1]) and (lines[i + 2] == '__malloc__)) ;\n'):
            del lines[i:i+2]

        #minilua merge
        if ('extern FILE *tmpfile(void)  __asm__("tmpfile64") __attribute__((__malloc__(fclose,1),\n' in lines[i+1]) \
                and ('__malloc__)) ;\n' in lines[i+2]):
            del lines[i:i+2]

        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__asm__("fopen64") __attribute__((__malloc__(fclose,1),\n' in lines[i+1]) and ('__malloc__)) ;\n' in
                                                                                                lines[i+2]):
            del lines[i:i+2]

        if 'void __attribute__((__visibility__("internal")))  merge_dummy_return' in lines[i+1]:
            del lines[i:i+1]
        i+=1

def _fix_source_freetype(lines: list[str]) -> None:
    i = 0
    while i < len(lines):
        line = lines[i]
        # freetype merge
        if 'ft_raccess_guess_table[5].func = & raccess_guess_vfat;' in line:
            lines.pop(i)
        if 't1cid_driver_class.load_glyph = & cid_slot_load_glyph;' in line:
            lines.pop(i)
        if 't1_driver_class.attach_file = & T1_Read_Metrics;' in line:
            lines.pop(i)
        if 'sfnt_interface.load_sbit_image = & tt_face_load_sbit_image;' in line:
            lines.pop(i)
        if 'sfnt_interface.load_eblc = & tt_face_load_eblc;' in line:
            lines.pop(i)
        if 'sfnt_interface.free_eblc = & tt_face_free_eblc;' in line:
            lines.pop(i)
        if 'tt_service_gx_multi_masters.set_mm_blend = (FT_Error (*)(FT_Face face , FT_UInt num_coords ,' in line:
            lines.pop(i)

        #freetype split
        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes ) \n' in lines[i+1]) \
                and ('__attribute__((__malloc__(fclose,1),\n' in lines[i+2]) and ('__malloc__)) ;\n' in lines[i+3]):
            del lines[i:i+3]

        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__attribute__((__malloc__(fclose,1),\n' in lines[i+1]) and ('__malloc__)) ;\n' in lines[i+2]):
            del lines[i:i+2]
        i+=1

def tigress_fixup(project: Project, file: Path) -> bool:
    # Read lines
    lines = open(file, "r").readlines()
    # Apply the right fixups depending on the project
    match project:
        case Project.ZLIB:
            _fix_source_zlib(lines)
        case Project.LZ4:
            _fix_source_lz4(lines)
        case Project.FREETYPE:
            _fix_source_freetype(lines)
        case Project.SQLITE:
            _fix_source_sqlite(lines)
        case Project.MINILUA:
            _fix_source_minilua(lines)
    # Write-back the file
    open(file, "w").writelines(lines)
    return True


def _get_funs_to_obfuscate(sample: Sample, obf_level, seed: int) -> list[str]:
    symbols = json.loads(sample.symbols_file.read_text())
    function_list = [v for v in symbols.values() if v != '']
    Random(seed).shuffle(function_list)  # shuffle elements

    candidate_functions = function_list[:int(obf_level / 100 * len(function_list))]
    return [f for f in candidate_functions if not f.startswith('_') and f not in FUN_BLACKLIST]


def get_mix1_parameters(sample: Sample, obf_level, seed: int) -> list[str]:
    
    error_functions = error_functions_zlib | error_functions_lz4 | error_functions_minilua | error_functions_sqlite

    candidate_functions = set(_get_funs_to_obfuscate(sample, obf_level, seed))
    candidate_functions -= error_functions
    candidate_functions = list(candidate_functions)
    
    return ["--Transform=Flatten", f"--Functions={','.join(candidate_functions)}",
            "--Transform=EncodeArithmetic", f"--Functions={','.join(candidate_functions)}",
            "--Transform=InitOpaque", "--Functions=main",
            "--Transform=AddOpaque", f"--Functions={','.join(candidate_functions)}"]


def get_mix2_parameters(sample: Sample, obf_level, seed: int, split_count: int) -> list[str]:
    params = get_mix1_parameters(sample, obf_level, seed)
    
    return params+[
        "--Transform=Split",
        f"--SplitCount={split_count}", f"--Functions={params[-1].replace('--Functions=', '')}"
    ]


def get_merge_parameters(sample: Sample, obf_level: int):
    
    # In order to have the complete list of functions that are available for obfuscation, need to rely on -O0 binary    
    # Retrieve symbols of the -O0 binary and filter out all unwanted functions
    symbols = json.loads(sample.symbols_file.read_text())
    functions_list = [v for v in symbols.values() if v != '']
    
    error_functions = error_functions_zlib | error_functions_lz4 | error_functions_minilua | error_functions_sqlite

    candidates_to_merge = {f for f in functions_list if 'i$nit' not in f and not f.startswith('_')}
    candidates_to_merge -= error_functions

    functions_to_merge = list(candidates_to_merge)[:int(len(candidates_to_merge) * obf_level / 100)]

    funtuples = list(zip(functions_to_merge[::2], functions_to_merge[1::2]))
    if len(functions_to_merge) % 2 != 0:
        funtuples.append(tuple(list(funtuples.pop(-1))+[functions_to_merge[-1]]))

    params = []
    for tup in funtuples:
        params.append("--Transform=Merge")
        params.append(f"--Functions={','.join(tup)}")
    # params.pop(0)  # remove first Transform merge as it will be added by the run_tigress command
    return params


def compile_tigress(sample: Sample) -> bool:
    args = [
        f"{sample.compiler.value}",
        f"-{sample.optimization.value}",
        "-D", '__DATE__="1970-01-01"',
        '-D', '__TIME__="00:00:00"',
        '-D', '__TIMESTAMP__="1970-01-01 00:00:00"',
        "-frandom-seed=123",
        "-fno-guess-branch-probability",
        "-lm",
        "-o", f"{sample.binary_file}",
        f"{sample.source_file}"
    ]
    p = subprocess.Popen(args, stdin=None, stdout=None, stderr=None)
    output, err = p.communicate()
    return p.returncode == 0
