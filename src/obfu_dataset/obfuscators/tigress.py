import os
import shutil
from pathlib import Path
import subprocess
import json
from random import Random

from obfu_dataset import ObPass, Sample
from obfu_dataset.projects import *

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
        f"--Transform=InitOpaque" if ObPass.OPAQUE else ""
        f"--Functions=main" if ObPass.OPAQUE else ""
        f"--Transform={PASS_CMDLINE[obfu]}" if not params else ""] + \
        params + \
        [f"--SplitKinds=deep,block,top" if ObPass.SPLIT else "",
        f"--SplitCount={split_count}" if ObPass.SPLIT else "",
        f"--Functions=%{fun_perc}",
        "--out=" + str(outfile),
        str(infile)
    ]

    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    return p.returncode == 0


def tigress_fixup(file):
    file_contents = open(file, 'r')
    fixed_file = str(file).replace('.c', '.fixed.c')
    fixed_contents = open(fixed_file, 'r')
    readlines = file_contents.readlines()
    fixed_readlines = []
    i=0
    while i<len(readlines):
        line = readlines[i]
        #zlib merge
        if 'configuration_table[0].func = & deflate_stored;' in line:
            i = i + 1
        if 'configuration_table[1].func = & deflate_fast;' in line:
            i = i + 1
        if 'configuration_table[2].func = & deflate_fast;' in line:
            i = i + 1
        if 'configuration_table[3].func = & deflate_fast;' in line:
            i = i + 1
        if 'configuration_table[4].func = & deflate_slow;' in line:
            i = i + 1
        if 'configuration_table[5].func = & deflate_slow;' in line:
            i = i + 1
        if 'configuration_table[6].func = & deflate_slow;' in line:
            i = i + 1
        if 'configuration_table[7].func = & deflate_slow;' in line:
            i = i + 1
        if 'configuration_table[8].func = & deflate_slow;' in line:
            i = i + 1
        if 'configuration_table[9].func = & deflate_slow;' in line:
            i = i + 1

        # freetype merge
        if 'ft_raccess_guess_table[5].func = & raccess_guess_vfat;' in line:
            i = i + 1
        if 't1cid_driver_class.load_glyph = & cid_slot_load_glyph;' in line:
            i = i + 1
        if 't1_driver_class.attach_file = & T1_Read_Metrics;' in line:
            i = i + 1
        if 'sfnt_interface.load_sbit_image = & tt_face_load_sbit_image;' in line:
            i = i + 1
        if 'sfnt_interface.load_eblc = & tt_face_load_eblc;' in line:
            i = i + 1
        if 'sfnt_interface.free_eblc = & tt_face_free_eblc;' in line:
            i = i + 1
        if 'tt_service_gx_multi_masters.set_mm_blend = (FT_Error (*)(FT_Face face , FT_UInt num_coords ,' in line:
            i = i + 1

        #zlib copy
        if 'extern FILE *tmpfile(void)  __attribute__((__malloc__(fclose,1), __malloc__)) ;\n' in line:
            i = i + 1

        #lz4 merge
        if 'void __attribute__((__visibility__("default")))  merge_dummy_return' in line:
            line = line.replace('void ', '')

        #minilua virtualize
        if ('__attribute__((__malloc__(fclose,1),\n' in readlines[i + 1]) and (readlines[i + 2] == '__malloc__)) ;\n'):
            i = i + 2
        if ('__attribute__((__malloc__(pclose,1),\n' in readlines[i + 1]) and (readlines[i + 2] == '__malloc__)) ;\n'):
            i = i + 2

        #minilua merge
        if ('extern FILE *tmpfile(void)  __asm__("tmpfile64") __attribute__((__malloc__(fclose,1),\n' in readlines[i+1]) \
                and ('__malloc__)) ;\n' in readlines[i+2]):
            i = i + 2

        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__asm__("fopen64") __attribute__((__malloc__(fclose,1),\n' in readlines[i+1]) and ('__malloc__)) ;\n' in
                                                                                                readlines[i+2]):
            i = i + 2

        if ('void __attribute__((__visibility__("internal")))  merge_dummy_return' in readlines[i+1]):
            i = i + 1

        #sqlite virtualize
        if '    *((void __attribute__((__overloaded__))  *)(' in readlines[i+1]:
            i = i + 2

        #sqlite flatten
        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) open_memstream)(char **__bufloc ,\n'
            in readlines[i+1]) and ('size_t *__sizeloc )  __attribute__((__malloc__(fclose,1),\n' in readlines[i+2]) and\
                ('__malloc__)) ;\n' in readlines[i+3]):
            i = i + 3

        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__asm__("fopen64") __attribute__((__malloc__(fclose,1),\n' in readlines[i+1]) and ('__malloc__)) ;\n'
                                                                                                in readlines[i+2]):
            i = i + 2

        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fopencookie)(void * __restrict  '
            '__magic_cookie ,\n' in readlines[i+1]) and ('char const   * __restrict  __modes ,\n' in readlines[i+2]) \
                and ('cookie_io_functions_t __io_funcs )  __attribute__((__malloc__(fclose,1),\n' in readlines[i+3]) \
                and ('__malloc__)) ;\n' in readlines[i+4]):
            i = i + 4

        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fmemopen)(void *__s ,\n' in readlines[i+1]) \
            and ('size_t __len ,\n' in readlines[i+2]) and ('char const   *__modes )  __attribute__((__malloc__(fclose,1),\n' in readlines[i+3]) \
            and ('__malloc__)) ;\n' in readlines[i+4]):
            i = i + 4

        if 'extern FILE *tmpfile64(void)  __attribute__((__malloc__(fclose,1), __malloc__)) ;\n' in readlines[i+1]:
            i = i + 1

        if ('extern FILE *fopen64(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__attribute__((__malloc__(fclose,1),\n' in readlines[i+1]) and ('__malloc__)) ;\n' in readlines[i+2]):
            i = i + 2

        if ('extern  __attribute__((__nothrow__)) void *( __attribute__((__warn_unused_result__,\n' in readlines[i+1]) and\
                ('__leaf__)) realloc)(void *__ptr , size_t __size )  __attribute__((__alloc_size__(2))) ;\n' in readlines[i+2]):
            i = i + 2

        if ('extern  __attribute__((__nothrow__)) void *( __attribute__((__warn_unused_result__,\n' in readlines[i+1]) and\
                ('__leaf__)) reallocarray)(void *__ptr , size_t __nmemb , size_t __size )  __attribute__((__malloc__(__builtin_free,1),\n' in readlines[i+2]) and\
                ('__malloc__(reallocarray,1), __alloc_size__(2,3))) ;\n' in readlines[i+3]):
            i = i + 3

        if ('extern  __attribute__((__nothrow__)) FILE *( __attribute__((__leaf__)) fdopen)(int __fd ,\n' in readlines[i+1]) \
                and ('char const   *__modes )  __attribute__((__malloc__(fclose,1),\n' in readlines[i+2]) \
                and ('__malloc__)) ;\n' in readlines[i+3]):
            i = i + 3

        #freetype split
        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes ) \n' in readlines[i+1]) \
                and ('__attribute__((__malloc__(fclose,1),\n' in readlines[i+2]) and ('__malloc__)) ;\n' in readlines[i+3]):
            i = i + 3

        if ('extern FILE *fopen(char const   * __restrict  __filename , char const   * __restrict  __modes )  '
            '__attribute__((__malloc__(fclose,1),\n' in readlines[i+1]) and ('__malloc__)) ;\n' in readlines[i+2]):
            i = i + 2
        #TODO check if ok
        i=i+1
        fixed_readlines.append(line)

    file_contents.close()
    fixed_contents.close()
    pathlib.unlink(file)
    final_path = Path(fixed_file).rename('.fixed.c', '.c')
    return final_path


def _get_funs_to_obfuscate(sample: Sample, obf_level, seed: int) -> list[str]:
    symbols = json.loads(sample.symbols_file.read_text())
    function_list = [v for v in symbols.values() if v != '']
    Random(seed).shuffle(function_list)  # shuffle elements

    candidate_functions = function_list[:int(obf_level / 100 * len(function_list))]
    return [f for f in candidate_functions if not f.startswith('_') and f not in FUN_BLACKLIST]


def get_mix1_parameters(sample: Sample, obf_level, seed: int) -> list[str]:
    candidate_functions = _get_funs_to_obfuscate(sample, obf_level, seed)
    return ["--Transform=Flatten", f"--Functions={','.join(candidate_functions)}",
            "--Transform=EncodeArithmetic", f"--Functions={','.join(candidate_functions)}",
            "--Transform=InitOpaque", "--Functions=main",
            "--Transform=AddOpaque", f"--Functions={','.join(candidate_functions)}"]


def get_mix2_parameters(sample: Sample, obf_level, seed: int, split_count: int) -> list[str]:
    params = get_mix1_parameters(sample, obf_level, seed)
    return params+[
        "--Transform=Split",
        f"--SplitCount={split_count}", f"--Functions={params[-1]}"
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
