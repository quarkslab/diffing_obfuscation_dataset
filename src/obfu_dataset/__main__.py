import click
import os
import shutil
import logging
import subprocess
import json
from idascript import MultiIDA, iter_binary_files, IDA

from obfu_dataset.types import Project, Obfuscator, ObPass, OptimLevel, Architecture, OLLVM_PASS, Compiler
from obfu_dataset.dataset import ObfuDataset

PROJ_OPT = [x.value for x in Project]
OBF_OPT = [x.value for x in Obfuscator]
PASS_OPT = [x.value for x in ObPass]
SEED_NUMBER=10
SPLIT_COUNT=2

def tigress_fixup(file): #TODO
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
def get_mix2_command(root_path, proj, obf_level, seed, ida_script, output_path) -> list[str]:
    # In order to have the complete list of functions that are available for obfuscation, need to rely on -O0 binary
    src_dir = root / proj.value / "sources"
    plain_binary = [f for f in src_dir.iterdir() if (f.suffix == '.exe') and ('O0' in f.name)][0]
    plain_src = [f for f in src_dir.iterdir() if (f.suffix == '.c')][0]
    symbols_path = plain_binary / '.json'
    if not symbols_path.exists():
        os.environ["IDA_PATH"] = shutil.which("ida")
        ida = IDA(src_binary, script_ida, [])
        ida.start()
        retcode = ida.wait()

    with open(symbols_path, 'r') as file:
        function_names = json.load(file)
    function_list = [v for v in function_names.values()]
    random.Random(s).shuffle(function_names)
    candidate_functions = function_names[:int(obf_level/ 100 * len(function_names))]
    candidate_functions = [f for f in candidate_functions if not f.startswith('_') and f != 'memchr' and f != 'printf'
                           and f != 'puts' and f != 'free' and f != 'putchar' and f != 'register_tm_clones' and
                           f != 'open' and f != 'memset' and f != 'sub_401020' and f != 'malloc' and f != 'vsnprintf'
                           and f != 'deregister_tm_clones' and f != 'snprintf' and f != 'close' and f != 'strlen' and
                           f != 'memcpy' and f != 'frame_dummy' and f != 'strerror' and f != 'read' and f != 'lseek'
                           and f != 'write' and f != 'calloc' and f != 'XXH_swap64' and f != 'fwrite' and f != 'memmove'
                           and f != 'fread' and f != 'XXH_swap32']

    functions_to_obfuscate = ','.join(candidate_functions)
    cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Flatten',
           '--Functions='+functions_to_obfuscate, '--Transform=EncodeArithmetic', '--Functions='+functions_to_obfuscate,
           '--Transform=InitOpaque', '--Functions=main', '--Transform=AddOpaque', '--Functions='+functions_to_obfuscate,
           '--Transform=Split', '--SplitCount='+str(SPLIT_COUNT), '--Functions='+functions_to_obfuscate,
           '--out='+str(output_path), plain_src]

    return cmd
def get_mix1_command(root_path, proj, obf_level, seed, ida_script, output_path) -> list[str]:
    # In order to have the complete list of functions that are available for obfuscation, need to rely on -O0 binary
    src_dir = root / proj.value / "sources"
    plain_binary = [f for f in src_dir.iterdir() if (f.suffix == '.exe') and ('O0' in f.name)][0]
    plain_src = [f for f in src_dir.iterdir() if (f.suffix == '.c')][0]
    symbols_path = plain_binary / '.json'
    if not symbols_path.exists():
        os.environ["IDA_PATH"] = shutil.which("ida")
        ida = IDA(src_binary, script_ida, [])
        ida.start()
        retcode = ida.wait()

    with open(symbols_path, 'r') as file:
        function_names = json.load(file)
    function_list = [v for v in function_names.values()]
    random.Random(s).shuffle(function_names)
    candidate_functions = function_names[:int(obf_level / 100 * len(function_names))]
    candidate_functions = [f for f in candidate_functions if not f.startswith('_') and f != 'memchr' and f != 'printf'
                           and f != 'puts' and f != 'free' and f != 'putchar' and f != 'register_tm_clones' and
                           f != 'open' and f != 'memset' and f != 'sub_401020' and f != 'malloc' and f != 'vsnprintf'
                           and f != 'deregister_tm_clones' and f != 'snprintf' and f != 'close' and f != 'strlen' and
                           f != 'memcpy' and f != 'frame_dummy' and f != 'strerror' and f != 'read' and f != 'lseek'
                           and f != 'write' and f != 'calloc' and f != 'XXH_swap64' and f != 'fwrite' and f != 'memmove'
                           and f != 'fread' and f != 'XXH_swap32']
    functions_to_obfuscate = ','.join(candidate_functions)
    cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed=' + str(seed),
                                   '--Transform=Flatten', '--Functions=' + functions_to_obfuscate,
                                   '--Transform=EncodeArithmetic', '--Functions=' + functions_to_obfuscate,
                                   '--Transform=InitOpaque', '--Functions=main', '--Transform=AddOpaque',
                                   '--Functions=' + functions_to_obfuscate, '--out=' + str(output_path), plain_src]
    return cmd

def get_merge_command(root, proj, obf_level, seed, script_ida, output_path):
    # In order to have the complete list of functions that are available for obfuscation, need to rely on -O0 binary
    src_dir = root / proj.value / "sources"
    plain_binary = [f for f in src_dir.iterdir() if (f.suffix == '.exe') and ('O0' in f.name)][0]
    plain_src = [f for f in src_dir.iterdir() if (f.suffix == '.c')][0]
    symbols_path = plain_binary / '.json'
    if not symbols_path.exists():
        os.environ["IDA_PATH"]=shutil.which("ida")
        ida=IDA(src_binary, script_ida, [])
        ida.start()
        retcode=ida.wait()
    
    with open(symbols_path, 'r') as file:
	    function_names = json.load(file)
    function_list = [v for v in function_names.values()]
    # Cleaning candidate functions
    error_functions = {'deregister_tm_clones', 'register_tm_clones', '__do_global_dtors_aux', 'frame_dummy', '_start', '_init', '_fini', 'zcalloc', 'zcfree', 'main', 'gzprintf'}
    error_functions = {'_fini','__do_global_dtors_aux', 'register_tm_clones','frame_dummy', 'LZ4F_compressBlock', 'LZ4F_compressBlockHC_continue', 'main','LZ4F_doNotCompressBlock','LZ4F_compressBlock_continue', 'LZ4F_compressBlockHC', 'deregister_tm_clones', '_start', '_init'}
    error_functions = {'deregister_tm_clones', 'register_tm_clones', '__do_global_dtors_aux', 'frame_dummy', '_start', '_init', '_fini', 'luaB_loadfile', 'math_sqrt', 'luaB_close', 'luaB_yieldable', 'luaB_xpcall', 'math_floor','searcher_C', 'utflen', 'db_setuservalue', 'luaB_pairs', 'db_getinfo','iter_auxlax', 'os_setlocale', 'sort', 'db_setlocal',  'luaB_rawequal', 'math_toint','math_exp', 'io_fclose', 'f_flush', 'luaO_pushfstring', 'hookf','math_randomseed', 'tpack', 'f_luaopen', 'luaG_runerror', 'str_format', 'db_getupvalue', 'os_rename', 'math_ult', 'math_type', 'str_unpack', 'gmatch', 'ipairsaux', 'dofilecont', 'arith_add', 'luaB_collectgarbage', 'math_cos', 'tremove', 'warnfcont', 'math_log', 'f_seek', 'io_readline', 'os_clock', 'tmove', 'str_len', 'luaB_warn', 'os_remove', 'math_modf',  'luaB_print', 'db_setmetatable', 'resume', 'panic', 'os_tmpname', 'luaB_cocreate', 'arith_unm','db_sethook','luaopen_math', 'luaB_cowrap','luaopen_coroutine', 'luaB_tonumber', 'll_loadlib', 'luaB_next', 'unroll', 'searcher_Lua', 'luaB_tostring','finishpcall','db_traceback','math_asin','io_open','str_reverse','math_acos','io_flush','os_getenv','luaopen_base','io_write', 'str_find','lua_gc', 'iter_auxstrict','luaB_select', 'f_call', 'math_min', 'll_searchpath','io_popen','lua_pushfstring','ll_require','f_read', 'str_char', 'str_pack','f_write','luaB_auxwrap', 'math_fmod', 'luaB_error', 'db_getregistry', 'str_lower', 'searcher_Croot', 'db_getlocal', 'tconcat', 'luaB_type', 'boxgc', 'dothecall', 'codepoint','str_upper', 'io_noclose', 'luaB_costatus', 'math_ceil','str_gsub', 'luaopen_table', 'io_close', 'os_execute', 'io_tmpfile', 'math_rad', 'db_gethook', 'str_match', 'f_close', 'os_date', 'luaopen_string', 'luaB_assert','gmatch_aux', 'luaopen_io','math_tan', 'luaB_ipairs', 'utfchar', 'luaL_error', 'luaB_pcall','luaB_rawlen','getF', 'io_output','os_exit','lua_newstate', 'pairscont', 'arith_pow','db_upvalueid','tinsert', 'luaopen_debug', 'warnfoff', 'closepaux', 'luaB_rawget', 'io_read', 'luaB_setmetatable', 'writer', 'io_input', 'math_atan', 'io_type', 'arith_mod', 'arith_mul', 'gctm', 'byteoffset', 'f_parser', 'db_setcstacklimit', 'db_upvaluejoin', 'luaB_coresume', 'l_alloc', 'warnfon', 'str_packsize', 'luaB_rawset', 'str_dump', 'iter_codes', 'str_sub', 'luaB_getmetatable', 'os_difftime','tunpack', 'arith_div',  'math_deg', 'math_sin', 'io_lines', 'tunpack','main','math_random', 'luaB_dofile', 'luaB_yield', 'f_gc', 'db_setupvalue','luaB_load', 'luaopen_package', 'arith_sub', 'db_getuservalue', 'db_debug', 'db_getmetatable', 'f_setvbuf', 'math_abs','f_tostrings', 'getS', 'math_max','searcher_preload','arith_idiv', 'os_difftime','generic_reader','f_lines','str_rep', 'luaB_corunning', 'os_time', 'luaopen_utf8', 'luaopen_os', 'io_pclose', 'f_tostring', 'str_byte'}
    error_functions = {'sqlite3_bind_text64', 'sqlite3_data_count', 'cellSizePtr', 'sqlite3_autovacuum_pages', 'sqlite3_str_vappendf', 'sqlite3_bind_blob', 'jsonExtractFunc', 'nth_valueFinalizeFunc', 'sqlite3_result_subtype', 'pthreadMutexInit', 'jsonReplaceFunc', 'selectRefLeave', 'sqlite3_malloc64', 'sqlite3_value_int64', 'sqlite3_changes', '__do_global_dtors_aux', 'sqlite3_hard_heap_limit64', 'lengthFunc', 'sqlite3_backup_finish', 'sqlite3_extended_result_codes', 'memdbAccess', 'memdbDlOpen', 'trimFunc', 'sqlite3_filename_journal', 'sqlite3_changes64', 'sqlite3_bind_null', 'sqlite3_realloc', 'nolockIoFinderImpl', 'sqlite3_blob_write', 'sqlite3_wal_checkpoint_v2', 'sqlite3ExprWalkNoop', 'sqlite3_serialize', 'sqlite3_stmt_status', 'cdateFunc', 'sqlite3_overload_function', 'sqlite3_thread_cleanup', 'getPageMMap', 'first_valueStepFunc', 'sqlite3_test_control', 'memdbGetLastError', 'unixUnlock', 'sqlite3_result_int64', 'sqlite3_system_errno', 'exprNodeIsConstant', 'sqlite3_context_db_handle', 'sqlite3_prepare', 'selectRefEnter', 'sqlite3_filename_wal', 'sqlite3_soft_heap_limit', 'sqlite3_prepare16_v3', 'pcache1Cachesize', 'renameColumnSelectCb', 'renameQuotefixExprCb', 'sqlite3_aggregate_count', 'unixWrite', 'sqlite3_str_appendall', 'unixSectorSize', 'percent_rankInvFunc', 'sqlite3_log', 'sqlite3_backup_step', 'memdbSync', 'sqlite3_blob_open', 'jsonEachFilter', 'noopMutexLeave', 'juliandayFunc', 'sqlite3MemShutdown', 'jsonEachOpenEach', 'pthreadMutexAlloc', 'hexFunc', 'groupConcatStep', 'binCollFunc', 'u', 'sqlite3_str_length', 'ntileValueFunc', 'sqlite3_compileoption_used', 'sqlite3_column_bytes', 'sqlite3_wal_autocheckpoint', 'memdbFullPathname', 'sqlite3_db_name', 'sqlite3_load_extension', 'sqlite3SelectWalkNoop', 'sqlite3_value_free', 'sqlite3_free_filename', 'memjrnlRead', 'compileoptionusedFunc', 'memdbWrite', 'pthreadMutexEnd', 'exprIdxCover', 'sqlite3_next_stmt', 'statInit', 'sqlite3_vfs_find', 'sqlite3OomClear', 'sqlite3MemRealloc', 'gatherSelectWindowsCallback', 'noopMutexInit', 'datetimeFunc', 'whereIsCoveringIndexWalkCallback', 'incrAggDepth', 'pthreadMutexEnter', 'unixLock', 'attachFunc', 'propagateConstantExprRewrite', 'sqlite3_column_double', 'sqlite3MemMalloc', 'exprRefToSrcList', 'jsonArrayStep', 'ctimestampFunc', 'unixDlClose', 'sqlite3_value_int', 'charFunc', 'vdbeRecordCompareString', 'jsonGroupInverse', 'sqlite3_status', 'convertCompoundSelectToSubquery', 'sqlite3_keyword_check', 'nth_valueStepFunc', 'sqlite3_total_changes', 'sqlite3_vtab_in_next', 'sqlite3WalDefaultHook', 'sqlite3_free_table', 'noopMutexEnter', 'sqlite3_result_int', 'resolveSelectStep', 'noopMutexTry', 'percent_rankStepFunc', 'unixOpen', 'countFinalize', 'sqlite3_limit', 'noopMutexEnd', 'sqlite3_reset_auto_extension', 'sqlite3_result_error16', 'sqlite3_set_authorizer', 'pcache1Rekey', 'sqlite3_expired', 'sqlite3_soft_heap_limit64', 'sqlite3_blob_close', 'sqlite3_result_zeroblob', 'strftimeFunc', 'lowerFunc', 'sqlite3_column_name', 'selectExpander', 'memdbTruncate', 'sqlite3_create_module_v2', 'sourceidFunc', 'zeroblobFunc', 'sqlite3_interrupt', 'memjrnlFileSize', 'openDirectory', 'pragmaVtabOpen', 'sumFinalize', 'memdbFetch', 'unixClose', 'sqlite3_declare_vtab', 'jsonValidFunc', 'sqlite3_mprintf', 'unixDlSym', 'unixShmLock', 'sqlite3_prepare_v3', 'memdbLock', 'unixGetLastError', 'first_valueFinalizeFunc', 'changes', 'sqlite3_aggregate_context', 'sqlite3_db_release_memory', 'ctimeFunc', 'sqlite3_str_value', 'compileoptiongetFunc', 'sqlite3_bind_blob64', 'sqlite3_backup_remaining', 'exprColumnFlagUnion', 'sqlite3_reset', 'memjrnlWrite', 'loadExt', 'sqlite3_blob_reopen', 'sqlite3_stmt_readonly', 'sqlite3_finalize', 'sqlite3_bind_pointer', 'jsonObjectFinal', 'replaceFunc', 'pcache1Init', 'sqlite3_free', 'sqlite3_memory_used', 'renameTableTest', 'frame_dummy', 'sqlite3SelectWalkFail', 'unicodeFunc', 'sqlite3RowSetDelete', 'last_valueFinalizeFunc', 'memdbRandomness', 'sqlite3_commit_hook', 'sqlite3_value_double', 'sqlite3_busy_timeout', 'sqlite3_result_text16', 'sqlite3WalkWinDefnDummyCallback', 'sqlite3_drop_modules', 'sqlite3_uri_key', 'sqlite3_stmt_isexplain', 'sqlite3_sql', 'sqlite3_mutex_try', 'timeFunc', 'noopMutexFree', 'avgFinalize', 'jsonEachBestIndex', 'btreeParseCellPtr', 'sqlite3WindowExtraAggFuncDepth', 'totalFinalize', 'memdbRead', 'sqlite3_bind_zeroblob64', 'sqlite3_str_errcode', 'sqlite3_column_text16', 'sqlite3_auto_extension', 'pragmaVtabRowid', 'jsonArrayLengthFunc', 'randomFunc', 'sqlite3_vtab_config', 'noopMutexAlloc', 'sqlite3_file_control', 'sqlite3_value_bytes', 'jsonPatchFunc', 'sqlite3_keyword_name', 'sqlite3NoopDestructor', 'pragmaVtabNext', 'sqlite3_str_appendchar', 'sqlite3TestExtInit', 'sqlite3_column_decltype', 'noopValueFunc', 'cume_distValueFunc', 'sqlite3_rollback_hook', 'sqlite3_msize', 'sqlite3_memory_highwater', 'sqlite3_str_new', 'sqlite3_snprintf', 'selectWindowRewriteExprCb', 'unixShmUnmap', 'sqlite3_value_type', 'sqlite3_stmt_busy', 'sqlite3_str_appendf', 'noopStepFunc', 'sqlite3_uri_boolean', 'unixShmMap', 'sqlite3_enable_shared_cache', 'renameUnmapSelectCb', 'sqlite3_keyword_count', 'unixDlOpen', 'memdbFileSize', 'pragmaVtabColumn', 'ntileStepFunc', 'sqlite3_mutex_free', 'pragmaVtabConnect', 'sqlite3_column_type', 'sqlite3_value_pointer', 'subtypeFunc', 'sqlite3SelectPopWith', 'nolockCheckReservedLock', 'groupConcatInverse', 'checkConstraintExprNode', 'sqlite3_value_blob', 'memdbOpen', 'pagerStress', 'sqlite3_profile', 'unixRead', 'instrFunc', 'unixDlError', 'sqlite3_uri_parameter', 'sqlite3_column_text', 'sqlite3_prepare_v2', 'jsonEachEof', 'pcache1Shutdown', 'sqlite3_update_hook', 'substrFunc', 'resolveRemoveWindowsCb', 'sqlite3_exec', 'dotlockUnlock', 'sqlite3_progress_handler', 'sqlite3_bind_double', '_fini', 'jsonArrayValue', 'sqlite3_db_mutex', 'last_insert_rowid', 'renameTableExprCb', 'jsonEachOpenTree', 'sqlite3_set_auxdata', 'versionFunc', 'signFunc', 'memdbFileControl', 'cume_distInvFunc', 'sqlite3_sourceid', 'errlogFunc', 'exprNodeIsDeterministic', 'p', 'renameColumnFunc', 'unixFullPathname', 'sqlite3_strlike', 'dotlockLock', 'sqlite3_column_value', 'pragmaVtabClose', 'sqlite3_expanded_sql', 'pcache1Pagecount', 'sqlite3_stricmp', 'sqlite3_result_error_nomem', 'sqlite3_result_error', 'sqlite3_complete', 'renameColumnExprCb', 'sqlite3_transfer_bindings', 'sqlite3_result_pointer', 'jsonQuoteFunc', 'sqlite3_mutex_enter', 'sqlite3_value_numeric_type', 'resolveExprStep', 'jsonEachNext', 'unixAccess', 'unixSync', 's', 'pragmaVtabBestIndex', 'countStep', 'sqlite3_value_frombind', 'selectWindowRewriteSelectCb', 'sqlite3MemFree', 'sqlite3VdbeFrameMemDel', 'jsonSetFunc', 'memdbClose', 'memdbUnfetch', 'm', 'sqlite3_realloc64', 'last_valueInvFunc', 'sqlite3_last_insert_rowid', 'randomBlob', 'rankValueFunc', 'sqlite3_str_append', 'analyzeAggregate', 'sqlite3_value_nochange', 'sqlite3_threadsafe', 'pragmaVtabEof', 'jsonObjectFunc', 'jsonTypeFunc', 'pcache1Fetch', 'impliesNotNullRow', 'sumStep', 'sqlite3_result_zeroblob64', 'jsonEachRowid', 'sqlite3_strnicmp', 'sqlite3_create_collation', 'exprNodeIsConstantOrGroupBy', 'sqlite3_database_file_object', 'sqlite3_status64', 'unixFileControl', 'sqlite3_value_text16be', 'sqlite3_db_cacheflush', 'sqlite3MemRoundup', 'memdbDeviceCharacteristics', 'recomputeColumnsUsedExpr', 'sqlite3_result_error_toobig', 'sqlite3_vtab_rhs_value', 'sqlite3_value_text', 'pthreadMutexTry', 'sqlite3MemSize', 'sqlite3_db_handle', 'sqlite3_result_error_code', 'sqlite3_value_dup', 'sqlite3_prepare16_v2', 'row_numberValueFunc', 'sqlite3_column_decltype16', 'sqlite3_create_module', 'sqlite3_value_subtype', 'sqlite3_release_memory', 'detachFunc', 'sqlite3_result_text64', 'unixCurrentTime', 'getPageNormal', 'unixShmBarrier', 'row_numberStepFunc', 'sqlite3_malloc', 'memdbDlClose', 'unixCheckReservedLock', 'sqlite3_bind_parameter_index', 'sqlite3_db_readonly', 'sqlite3_cancel_auto_extension', 'sqlite3_prepare16', 'sqlite3_db_filename', 'sqlite3_db_config', 'sqlite3_result_text', 'sqlite3_str_reset', 'unixGetSystemCall', 'unixUnfetch', 'dropColumnFunc', 'sqlite3_close_v2', 'printfFunc', 'sqlite3_backup_init', 'jsonEachDisconnect', 'unixDeviceCharacteristics', 'sqlite3_create_function_v2', 'nolockLock', 'disallowAggregatesInOrderByCb', 'sqlite3_clear_bindings', 'quoteFunc', 'sqlite3_vtab_in_first', 'unixFileSize', 'sqlite3VdbeError', 'dotlockClose', 'sqlite3_value_text16le', 'ntileInvFunc', 'typeofFunc', 'sqlite3_errmsg16', 'nullifFunc', 'sqlite3_bind_zeroblob', 'sqlite3_value_text16', 'countInverse', 'pcache1Shrink', 'sqlite3_vtab_in', 'rankStepFunc', 'pcache1Destroy', 'unixGetpagesize', 'sqlite3MemInit', 'sqlite3_open16', 'sqlite3_extended_errcode', 'vdbeSorterCompareInt', 'pcache1Create', 'sqlite3_column_count', 'g', 'sqlite3_errcode', 'sqlite3_blob_read', 'sqlite3_column_name16', 'minmaxStep', 't', 'sqlite3_libversion_number', 'sqlite3_randomness', 'percent_rankValueFunc', 'roundFunc', '_start', 'sqlite3_bind_int64', 'j', 'jsonEachColumn', 'sqlite3_result_blob64', 'memdbSleep', 'btreeParseCellPtrNoPayload', 'sqlite3_column_blob', 'unixRandomness', 'posixIoFinderImpl', 'sqlite3_create_collation_v2', 'sqlite3_column_int64', 'sqlite3_create_filename', 'memjrnlSync', 'sqlite3_result_blob', 'sqlite3_create_collation16', 'sqlite3_strglob', 'sqlite3_vtab_distinct', 'last_valueValueFunc', 'sqlite3_filename_database', 'sqlite3_vsnprintf', 'jsonRemoveFunc', 'upperFunc', 'renameTableSelectCb', 'sqlite3_step', 'sqlite3_trace', 'sqlite3_value_bytes16', 'unixCurrentTimeInt64', 'memdbDlSym', 'sqlite3_backup_pagecount', 'sqlite3_trace_v2', 'statPush', 'sqlite3_vtab_collation', 'sqlite3_result_value', 'sqlite3_uri_int64', 'sqlite3_create_function16', 'pthreadMutexLeave', 'dotlockCheckReservedLock', 'sqlite3JsonTableFunctions', 'sqlite3_collation_needed', '_init', 'btreeParseCellPtrIndex', 'sqlite3_collation_needed16', 'total_changes', 'sqlite3_vfs_register', 'jsonEachConnect', 'sqlite3_result_null', 'havingToWhereExprCb', 'memjrnlClose', 'sqlite3_wal_checkpoint', 'fixExprCb', 'sqlite3_busy_handler', 'jsonArrayFinal', 'memdbCurrentTimeInt64', 'selectAddSubqueryTypeInfo', 'vdbeSorterCompareText', 'memdbDlError', 'sqlite3_errmsg', 'renameUnmapExprCb', 'minMaxFinalize', 'sqlite3_vtab_on_conflict', 'pragmaVtabDisconnect', 'sqlite3_sleep', 'sqlite3_vfs_unregister', 'unixNextSystemCall', 'dateFunc', 'dense_rankValueFunc', 'sqlite3_bind_parameter_name', 'sqlite3_bind_value', 'sqlite3_error_offset', 'unixDelete', 'sqlite3_blob_bytes', 'sqlite3_txn_state', 'sqlite3_wal_hook', 'unixepochFunc', 'cume_distStepFunc', 'sqlite3_close', 'unixSleep', 'sqlite3_mutex_leave', 'register_tm_clones', 'pcache1Truncate', 'fixSelectCb', 'sqlite3_result_text16be', 'sqlite3_get_autocommit', 'sqlite3_get_auxdata', 'sqlite3_vmprintf', 'sqlite3_get_table', 'sqlite3_result_text16le', 'sqlite3_bind_int', 'pragmaVtabFilter', 'sumInverse', 'groupConcatValue', 'sqlite3WalkerDepthDecrease', 'sqlite3VdbeRecordCompare', 'sqlite3_db_status', 'last_valueStepFunc', 'jsonObjectValue', 'vdbeRecordCompareInt', 'sqlite3_deserialize', 'memjrnlTruncate', 'sqlite3_bind_text', 'nolockUnlock', 'agginfoPersistExprCb', 'vdbeSorterCompare', 'sqlite3_column_bytes16', 'unixSetSystemCall', 'sqlite3_create_function', 'sqlite3_create_window_function', 'sqlite3_bind_parameter_count', 'dense_rankStepFunc', 'pthreadMutexFree', 'sqlite3_user_data', 'sqlite3_open', 'gatherSelectWindowsSelectCallback', 'getPageError', 'renumberCursorsCb', 'cellSizePtrTableLeaf', 'sqlite3_column_int', 'statGet', 'pcache1Unpin', 'nolockClose', 'likeFunc', 'renameQuotefixFunc', 'absFunc', 'sqlite3_mutex_alloc', 'sqlite3_table_column_metadata', 'cellSizePtrNoPayload', 'groupConcatFinalize', 'sqlite3_open_v2', 'unixTruncate', 'sqlite3_errstr', 'sqlite3_complete16', 'jsonArrayFunc', 'minmaxFunc', 'sqlite3_result_double', 'jsonEachClose', 'posixOpen', 'sqlite3_str_finish', 'sqlite3_libversion', 'sqlite3WalkerDepthIncrease', 'sqlite3_bind_text16', 'deregister_tm_clones', 'sqlite3_compileoption_get', 'unixFetch', 'minMaxValue', 'sqlite3_vtab_nochange', 'sqlite3_total_changes64', 'dotlockIoFinderImpl', 'jsonObjectStep', 'renameTableFunc', 'sqlite3_set_last_insert_rowid', 'jsonPrintf', 'exprDup', 'walkExpr', 'execSqlF', 'sqlite3ExprAffinity', 'sqlite3VdbeExplain', 'checkAppendMsg', 'sqlite3NestedParse', 'sqlite3ExprIfTrue', 'sqliteDefaultBusyCallback', 'sqlite3ExprDelete', 'sqlite3SchemaClear', 'rtrimCollFunc', 'agginfoFree', 'sqlite3DeleteTable', 'analysisLoader', 'sqlite3_config', 'sqlite3ErrorMsg', 'sqlite3DeleteReturning', 'getDigits', 'sqlite3MPrintf', 'sqlite3SelectDelete','pagerUndoCallback', 'vdbeSorterFlushThread'} #TODO gerer le cas freetypessss

    candidates_to_merge = list({f for f in functions_list if 'i$nit' not in f} - error_functions)
    if '' in candidates_to_merge:
        candidates_to_merge.remove('')

	functions_to_merge = candidates_to_merge[:int(len(candidates_to_merge) * obf_level/100)]
	    
	cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed)]
	# If the number of candidate is even, create pairs for merging
    if len(functions_to_merge) % 2 == 0:
        i=0
        while i<len(functions_to_merge):
            cmd.append('--Transform=Merge')
            cmd.append('--Functions='+str(functions_to_merge[i])+','+str(functions_to_merge[i+1]))
            i=i+2
	# If the number of candidate is odd, create pairs and one trio
    if len(functions_to_merge) % 2 != 0:
        i=0
        while i<len(functions_to_merge)-3:
            cmd.append('--Transform=Merge')
            cmd.append('--Functions='+str(functions_to_merge[i])+','+str(functions_to_merge[i+1]))
            i=i+2
        cmd.append('--Transform=Merge')
        cmd.append('--Functions='+str(functions_to_merge[-3])+','+str(functions_to_merge[-2])+','+str(functions_to_merge[-1]))
    
    cmd.append('--out=' + str(ouput_path))
    cmd.append(str(plain_src))
    return cmd

def gen_ollvm_obfuscated(root, proj, obf, obf_level, seed, script_ida):
    src_dir = root / proj.value / "sources"
    #In order to have the complete list of functions that are available for obfuscation, need to rely on -O0 binary
    plain_binary = [f for f in src_dir.iterdir() if (f.suffix == '.exe') and ('O0' in f.name)][0]
    plain_src = [f for f in src_dir.iterdir() if (f.suffix == '.c')][0]
    symbols_path = plain_binary / '.json'
    if not symbols_path.exists():
        os.environ["IDA_PATH"]=shutil.which("ida")
        ida=IDA(src_binary, script_ida, [])
        ida.start()
        retcode=ida.wait()
    
    with open(symbols_path, 'r') as file:
	    function_names = json.load(file)
    function_list = [v for v in function_names.values()]
    random.Random(SEED_NUMBER).shuffle(function_names)
    random.Random(seed).shuffle(function_names)
    candidate_functions = shuffle_functions[:int(obf_level/100*len(function_names))]
            
    #Load the .c file contents
    with open(src_binary, 'r') as out :
        readlines = out.readlines()
                
    for func in candidate_functions:
        #Omit these functions
        if (func == 'snprintf') or (func == 'compress_block') or (func == 'deflate_huff') or (func == 'inflate_table') or (func == 'printf') or (func=='strlen') or (func=='gzprintf') or (func == 'FT_Render_Glyph_Internal') or (func == 'psh_blues_scale_zones'):
            continue
            
        #Candidate lines to add pragma
        candidates = [(i, line) for (i, line) in enumerate(readlines) if (
        (' '+func+'(' in line) or 
        ('*'+func+'(' in line)) and 
        (';' not in line) and
        (':' not in line) and 
        ('\\' not in line) and 
        (' '+func+'()' not in line) and 
        ('if ' not in line) and 
        ('return ' not in line) and 
        ('=' not in line) and 
        ('if' not in line) and 
        (not line.startswith('  '+func)) and 
        (not line.startswith('    '+func)) and 
        (not line.startswith('      '+func)) and 
        (not line.startswith('   || ')) and 
        (not line.startswith('          '+func)) and 
        (not line.startswith('           '+func)) and 
        (re.match("[ ]*"+func, line)==None) and 
        ('>' not in line) and 
        ('#' not in line) and 
        ('^' not in line) and 
        (not line.startswith('   && '+func)) and 
        (not line.startswith('     || '+func)) and 
        (not line.startswith('     && '+func)) and 
        ('ENC' not in line) and 
        (not line.startswith('          + '+func)) 
        and (not line.startswith('           + ')) 
        and (not line.startswith('  '+func)) and 
        (' switch(' not in line) and 
        ('/2' not in line) and 
        (not line.startswith('       && '+func)) 
        and (' while(' not in line) and 
        (not line.startswith('         || '+func)) and
        (not line.startswith('           && '+func)) and
        (not line.endswith('&&\n')) and 
        (not line.startswith('\t  '+func)) and
        (not line.startswith('\t\t\t\t\t\t  '+func)) and
        (not line.startswith('\t\t\t\t\t\t '+func)) and
        (not line.startswith('\t\t\t\t\t   '+func)) and
        (not line.startswith('\t\t  '+func)) and
        ('? '+func not in line) and 
        (not line.startswith('\t\t '+func)) and
        (not line.startswith('\t\t\t '+func)) and 
        (not line.startswith('\t\t\t  ')) and 
        (not line.startswith('\t\t  '+func)) and 
        ('switch ( '+func not in line) and 
        (not line.startswith('\t\t   '+func)) and 
        ('\t' not in line)] #TODO refine the list by removing doublons
        
        #Dealing with exceptions
        if len(candidates)==0: #Imported functions
            continue
        for c in candidates : #Invalid candidate
            if ('{' not in c[1]) and c[1].endswith('\n'):
                if ('{' not in readlines[c[0]+1]):
                    candidates.remove(c)
        if func=='sqlite3StrAccumFinish':
            first_idx, line = candidates[0][0], candidates[0][1]                                                                                     
        elif len(candidates)==1 : 
            first_idx, line = candidates[-1][0], candidates[-1][1]
        else : 
            if func=='sqlite3StrAccumFinish':
                first_idx, line = candidates[0][0], candidates[0][1]
            if (re.match("[ ]*"+func, candidates[-1][1])!=None):
                first_idx, line = candidates[-2][0], candidates[-2][1]
            else :
                first_idx, line = candidates[-1][0], candidates[-1][1]
        
        first_idx, line = candidates[0][0], candidates[0][1]
        signature = line.split(func)[0]
                
        if signature.startswith('static') or signature.startswith('LUA_API') or signature.startswith('l_noret') or signature.startswith('LUALIB_API') or signature.startswith('SQLITE_PRIVATE') or signature.startswith('SQLITE_API') or signature.startswith('FT_LOCAL') or signature.startswith('FT_LOCAL_DEF') or signature.replace(' ', '').startswith('FT_Error') or signature.startswith('  static') or signature.startswith('  FT_LOCAL_DEF') or signature.startswith('  FT_EXPORT_DEF') or signature.startswith('  FT_BASE_DEF'):
            args = line.split(func)[1].replace('{', '')
            end_args_cpt = 1
            while ')' not in args: #Declaring the signature takes more than 1 line
                args += readlines[first_idx+end_args_cpt].replace('\n', '').replace('{', '')
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
                    readlines.insert(first_idx+1, signature + func + args + '() __attribute((__annotate__(("sub"))));\n') 
                    readlines.insert(first_idx+2, signature + func + args + '() __attribute((__annotate__(("bcf"))));\n') 
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
                    readlines.insert(first_idx+1, signature + func + '() __attribute((__annotate__(("sub"))));\n') 
                    readlines.insert(first_idx+2, signature + func + '() __attribute((__annotate__(("bcf"))));\n')
                    
    obf_dir = root / proj.value / "obfuscated" / "ollvm"/ obf.value / str(obf_level)
    obf_basename = proj.value + "_ollvm_clang_x64_" + obf.value + '_' + str(obf_level) + '_' + str(seed) + '.c'

    with open(obf_dir / obf_basename, 'w') as out:
        for line in readlines : 
            out.write(line)
    return obf_dir / obf_basename
            
@click.group(context_settings={'help_option_names': ['-h', '--help']})
def main():
    pass


@main.command(name="ls")
def list():
    pass


@main.command(name="download-plain")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.argument("project", type=click.Choice(PROJ_OPT), nargs=-1)
def download_plain(root: str, project: tuple[str]):

    dataset = ObfuDataset(root)

    for proj in (Project(x) for x in project):
        dataset.download_plain(proj)

@main.command(name="download-obfuscated")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
@click.option("-p", "--project", type=click.Choice(PROJ_OPT), required=True, help="Project to download")
@click.option("-o", "--obfuscator", type=click.Choice(OBF_OPT), default=None, required=False, help="Obfuscator to select (all if none)")
@click.option("-op", "--obf-pass", type=click.Choice(PASS_OPT), default=None, required=False, help="Obfuscation pass to download (all if none)")
def download_obfuscated(root: str, project: tuple[str], obfuscator: str|None, obf_pass: str|None):

    dataset = ObfuDataset(root)

    for proj in (Project(x) for x in project):
        obfs = [Obfuscator(obfuscator)] if obfuscator else list(Obfuscator)
        for obf in obfs:
            passes = [ObPass(obf_pass) if obf_pass else list(ObPass)]
            for p in passes:
                dataset.download_obfuscated(proj, obf, p)

@main.command(name="download-all")
@click.option('-r', "--root", type=click.Path(), required=True, help="Dataset root directory")
def download_all(root: str):
    dataset = ObfuDataset(root)
    dataset.download_all()


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
        dataset.download_plain(proj)
        src_dir = dataset.root / proj.value / "sources"
        src_file = [f for f in src_dir.iterdir() if f.suffix == '.c'][0]
        for obf in ObPass:
            obf_path = Path(dataset.root_path) / proj.value / "obfuscated" / "tigress" / obf.value
            for obf_level in range(10, 101, 10):
                level_path = obf_path / str(obf_level)
                level_path.mkdir(parent=True)
                for seed in range(1, SEED_NUMBER+1):
                    output_path = level_path / proj.value + '_tigress_gcc_x64_' + obf.value + '_' + str(obf_level) + '_' + str(seed) + '.c'
                    match obf.value:
                        case "copy":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Copy', '--Functions=%'+str(obf_level), '--out='+str(ouput_path), src_file]
                        
                        case "merge":
                            cmd = get_merge_command(dataset.root_path, proj.value, obf_level, seed, ida_script, output_path)

                        case "split":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Split', '--Functions=%'+str(obf_level), '--SplitKinds=deep,block,top', '--SplitCount='+str(SPLIT_COUNT), '--out='+str(ouput_path), src_file]
                           
                        case "CFF":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Flatten', '--Functions=%'+str(obf_level), '--out='+str(ouput_path), src_file]
                            
                        case "opaque":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=InitOpaque', '--Functions=main', '--Transform=AddOpaque', '--Functions=%'+str(obf_level), '--out='+str(output_path), src_file]
                            
                        case "virtualize":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=Virtualize', '--Functions=%'+str(obf_level), '--out='+str(ouput_path), src_file]
                            
                        case "encodearith":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=EncodeArithmetic', '--Functions=%'+str(obf_level), '--out='+str(ouput_path), src_file]
                            
                        case "encodeliteral":
                            cmd = ['tigress', '--Environment=x86_64:Linux:Gcc:4.6', '--Seed='+str(seed), '--Transform=EncodeLiterals', '--Functions=%'+str(obf_level), '--out='+str(ouput_path), src_file]
                            
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
                        
                    p = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                    output, err = p.communicate()
                    rc = p.returncode
                    logging.info('Tigress file:', filename, 'was generated with return code:', rc)

                            
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
                            logging.info('OLLVM file:', filename, 'was generated at location:', obfuscated_file)

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
                logging.info('Tigress file:', filename, 'was compiled with return code:', rc)
            
    #OLLVM
    #TODO CHECK OLLVM PATH 
    ollvm_install = #TODO
    use_ollvm14 = False
    if :
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
                            cmd = [ollvm_install + '_build/bin/clang', optim.value, '-D', '__DATE__="1970-01-01"', '-D', '__TIME__="00:00:00"', '-D', '__TIMESTAMP__="1970-01-01 00:00:00"', '-frandom-seed=123', '-o', output_bin, file, '-fpass-plugin=' + ollvm_install + '_build/lib/Ollvm.so', '-Xclang', '-load', '-Xclang', ollvm_install + '_build/lib/Ollvm.so']
                            
                        case "minilua":
                            cmd = [ollvm_install + '_build/bin/clang', optim.value, '-lm', '-D', '__DATE__="1970-01-01"', '-D', '__TIME__="00:00:00"', '-D', '__TIMESTAMP__="1970-01-01 00:00:00"', '-frandom-seed=123', '-o', output_bin, file, '-fpass-plugin=' + ollvm_install + '_build/lib/Ollvm.so', '-Xclang', '-load', '-Xclang', ollvm_install + '_build/lib/Ollvm.so']
                            
                else:
                    match proj.value:
                        case "zlib" | "lz4" | "freetype" | "sqlite":
                            cmd = [path_to_the/build/bin/clang test.c -o test -mllvm -sub -mllvm -fla] #TODO
                        case "minilua":
                            cmd = [path_to_the/build/bin/clang test.c  -lm -o test -mllvm -sub -mllvm -fla] #TODO
                            
                p = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
                output, err = p.communicate()
                rc = p.returncode
                logging.info('OLLVM file:', filename, 'was compiled with return code:', rc)
        
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
    files = Path(directory).glob("*")
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
