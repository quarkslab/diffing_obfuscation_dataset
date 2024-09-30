import random
import re
from obfu_dataset import ObPass, Sample
from pathlib import Path
import clang.cindex


OLLVM_PASS = [
    ObPass.CFF,
    ObPass.OPAQUE,
    ObPass.ENCODEARITH,
    ObPass.CFF_ENCODEARITH_OPAQUE
]

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
    return f"__attribute__(({s}))"


def gen_ollvm_annotated_source(dst_file: Path, sample: Sample, obpass: ObPass, obf_level: int, seed: int):
    symbols = sample.get_symbols()



def gen_ollvm_annotated_source(sample: Sample, output_file, obf, obf_level, seed):
    src_dir = root / proj.value / "sources"
    # In order to have the complete list of functions that are available for obfuscation, need to rely on -O0 binary
    plain_binary = [f for f in src_dir.iterdir() if (f.suffix == '.exe') and ('O0' in f.name)][0]
    plain_src = [f for f in src_dir.iterdir() if (f.suffix == '.c')][0]
    symbols_path = plain_binary / '.json'
    if not symbols_path.exists():
        os.environ["IDA_PATH"] = shutil.which("ida")
        ida = IDA(plain_binary, script_ida, [])
        ida.start()
        retcode = ida.wait()

    with open(symbols_path, 'r') as file:
        function_names = json.load(file)
    function_list = [v for v in function_names.values()]
    random.Random(SEED_NUMBER).shuffle(function_names)
    random.Random(seed).shuffle(function_names)
    candidate_functions = function_names[:int(obf_level / 100 * len(function_names))]

    # Load the .c file contents
    with open(plain_src, 'r') as out:
        readlines = out.readlines()

    for func in candidate_functions:
        # Omit these functions
        if (func == 'snprintf') or (func == 'compress_block') or (func == 'deflate_huff') or (
                func == 'inflate_table') or (func == 'printf') or (func == 'strlen') or (func == 'gzprintf') or (
                func == 'FT_Render_Glyph_Internal') or (func == 'psh_blues_scale_zones'):
            continue

        # Candidate lines to add pragma
        candidates = [(i, line) for (i, line) in enumerate(readlines) if (
                (' ' + func + '(' in line) or
                ('*' + func + '(' in line)) and
                      (';' not in line) and
                      (':' not in line) and
                      ('\\' not in line) and
                      (' ' + func + '()' not in line) and
                      ('if ' not in line) and
                      ('return ' not in line) and
                      ('=' not in line) and
                      ('if' not in line) and
                      (not line.startswith('  ' + func)) and
                      (not line.startswith('    ' + func)) and
                      (not line.startswith('      ' + func)) and
                      (not line.startswith('   || ')) and
                      (not line.startswith('          ' + func)) and
                      (not line.startswith('           ' + func)) and
                      (re.match("[ ]*" + func, line) == None) and
                      ('>' not in line) and
                      ('#' not in line) and
                      ('^' not in line) and
                      (not line.startswith('   && ' + func)) and
                      (not line.startswith('     || ' + func)) and
                      (not line.startswith('     && ' + func)) and
                      ('ENC' not in line) and
                      (not line.startswith('          + ' + func))
                      and (not line.startswith('           + '))
                      and (not line.startswith('  ' + func)) and
                      (' switch(' not in line) and
                      ('/2' not in line) and
                      (not line.startswith('       && ' + func))
                      and (' while(' not in line) and
                      (not line.startswith('         || ' + func)) and
                      (not line.startswith('           && ' + func)) and
                      (not line.endswith('&&\n')) and
                      (not line.startswith('\t  ' + func)) and
                      (not line.startswith('\t\t\t\t\t\t  ' + func)) and
                      (not line.startswith('\t\t\t\t\t\t ' + func)) and
                      (not line.startswith('\t\t\t\t\t   ' + func)) and
                      (not line.startswith('\t\t  ' + func)) and
                      ('? ' + func not in line) and
                      (not line.startswith('\t\t ' + func)) and
                      (not line.startswith('\t\t\t ' + func)) and
                      (not line.startswith('\t\t\t  ')) and
                      (not line.startswith('\t\t  ' + func)) and
                      ('switch ( ' + func not in line) and
                      (not line.startswith('\t\t   ' + func)) and
                      ('\t' not in line)]  # TODO refine the list by removing doublons

        # Dealing with exceptions
        if len(candidates) == 0:  # Imported functions
            continue
        for c in candidates:  # Invalid candidate
            if ('{' not in c[1]) and c[1].endswith('\n'):
                if ('{' not in readlines[c[0] + 1]):
                    candidates.remove(c)

        first_idx, line = candidates[0][0], candidates[0][1]
        signature = line.split(func)[0]

        if func == 'sqlite3StrAccumFinish':
            first_idx, line = candidates[0][0], candidates[0][1]
        elif len(candidates) == 1:
            first_idx, line = candidates[-1][0], candidates[-1][1]
        else:
            if func == 'sqlite3StrAccumFinish':
                first_idx, line = candidates[0][0], candidates[0][1]
            if (re.match("[ ]*" + func, candidates[-1][1]) != None):
                first_idx, line = candidates[-2][0], candidates[-2][1]
            else:
                first_idx, line = candidates[-1][0], candidates[-1][1]

        if signature.startswith('static') or signature.startswith('LUA_API') or signature.startswith(
                'l_noret') or signature.startswith('LUALIB_API') or signature.startswith(
                'SQLITE_PRIVATE') or signature.startswith('SQLITE_API') or signature.startswith(
                'FT_LOCAL') or signature.startswith('FT_LOCAL_DEF') or signature.replace(' ', '').startswith(
                'FT_Error') or signature.startswith('  static') or signature.startswith(
                '  FT_LOCAL_DEF') or signature.startswith('  FT_EXPORT_DEF') or signature.startswith('  FT_BASE_DEF'):
            args = line.split(func)[1].replace('{', '')
            end_args_cpt = 1
            while ')' not in args:  # Declaring the signature takes more than 1 line
                args += readlines[first_idx + end_args_cpt].replace('\n', '').replace('{', '')
                end_args_cpt += 1

            match obf.value:
                case "CFF":
                    readlines.insert(first_idx, signature + func + args + '() __attribute((__annotate__(("fla"))));\n')
                case "opaque":
                    readlines.insert(first_idx, signature + func + args + '() __attribute((__annotate__(("bcf"))));\n')
                case "encodearith":
                    readlines.insert(first_idx, signature + func + args + '() __attribute((__annotate__(("sub"))));\n')
                case "mix-1":
                    readlines.insert(first_idx, signature + func + args + '() __attribute((__annotate__(("fla"))));\n')
                    readlines.insert(first_idx + 1,
                                     signature + func + args + '() __attribute((__annotate__(("sub"))));\n')
                    readlines.insert(first_idx + 2,
                                     signature + func + args + '() __attribute((__annotate__(("bcf"))));\n')
        else:
            match obf.value:
                case "CFF":
                    readlines.insert(first_idx, signature + func + '() __attribute((__annotate__(("fla"))));\n')
                case "opaque":
                    readlines.insert(first_idx, signature + func + '() __attribute((__annotate__(("bcf"))));\n')
                case "encodearith":
                    readlines.insert(first_idx, signature + func + '() __attribute((__annotate__(("sub"))));\n')
                case "mix-1":
                    readlines.insert(first_idx, signature + func + '() __attribute((__annotate__(("fla"))));\n')
                    readlines.insert(first_idx + 1, signature + func + '() __attribute((__annotate__(("sub"))));\n')
                    readlines.insert(first_idx + 2, signature + func + '() __attribute((__annotate__(("bcf"))));\n')

    obf_dir = root / proj.value / "obfuscated" / "ollvm" / obf.value / str(obf_level)
    obf_basename = proj.value + "_ollvm_clang_x64_" + obf.value + '_' + str(obf_level) + '_' + str(seed) + '.c'

    with open(obf_dir / obf_basename, 'w') as out:
        for line in readlines:
            out.write(line)
    return obf_dir / obf_basename