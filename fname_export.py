import ida_auto
import idaapi
import ida_pro
import idautils
import ida_funcs
import json
import pathlib
import ida_nalt
ida_auto.auto_wait()

path = pathlib.Path(ida_nalt.get_input_file_path())
func_names_ea = {p:ida_funcs.get_func_name(p) for p in idautils.Functions()}
with open(path.parent / 'func_names.json', 'w') as output:
	json.dump(func_names_ea, output)

ida_pro.qexit(0)
