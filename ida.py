import io
import os
import pathlib
import sys
import zipfile

import requests

cwd = pathlib.Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])

bida_path = cwd / "./bromaida"
if not bida_path.exists():
    print(f"Extracting BromaIDA from {os.environ["BROMA_IDA_REPO"]}@{os.environ["BROMA_IDA_BRANCH"]}...")

    broma_ida_url = (
        f"https://github.com/{os.environ["BROMA_IDA_REPO"]}/archive/refs/heads/{os.environ["BROMA_IDA_BRANCH"]}.zip"
    )
    res = requests.get(broma_ida_url)
    res.raise_for_status()

    bida_path.mkdir(exist_ok=True)

    with zipfile.ZipFile(io.BytesIO(res.content)) as zip_file:
        zip_file.extractall(bida_path)

    # since the zip has an inner folder "BromaIDA-master"
    [_, repo_name] = os.environ["BROMA_IDA_REPO"].split("/")
    inner_dir = bida_path / f"{repo_name}-{os.environ["BROMA_IDA_BRANCH"]}"
    for item in inner_dir.iterdir():
        item.move(bida_path / item.name)

    inner_dir.rmdir()

sys.path.insert(0, sys.argv[2])
sys.path.insert(0, str(bida_path.absolute()))

import json

import dotenv
import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idaapi
import idautils
import idc
from broma_ida.broma.importer import BromaImporter
from broma_ida.data.data_manager import DataManager
from broma_ida.utils import IDAUtils

dotenv.load_dotenv(cwd / ".env")

print("Waiting for IDA to do its shit...")
ida_auto.auto_wait()

# usage taken from bromaida
print("Loading DataManager...")
DataManager().init(bida_path / "broma_ida" / "shelf")

# usage also taken from bromaida
print("Invoking BromaImporter...")
broma_importer = BromaImporter(IDAUtils.get_platform(), pathlib.Path(os.environ["BINDINGS_PATH"]))
broma_importer.parse_bromas()
broma_importer.import_into_idb()


def get_pseudocode(func_ea):
    if not ida_hexrays.init_hexrays_plugin():
        return None

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return None

    return "\n".join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())


def get_assembly(func_ea):
    f = ida_funcs.get_func(func_ea)
    if not f:
        return None

    lines = []
    ea = f.start_ea

    while ea < f.end_ea:
        line = idc.generate_disasm_line(ea, 0)
        if line:
            lines.append(ida_lines.tag_remove(line))
        ea = idaapi.next_head(ea, f.end_ea)

    return "\n".join(lines)


func_count = sum(1 for _ in idautils.Functions())
print(f"!~~{func_count}")

for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    print(f"""
        !~~{
            json.dumps({
                "start": f.start_ea,
                "end": f.end_ea,
                "name": ida_funcs.get_func_name(ea),
                "pseudocode": get_pseudocode(ea),
                "assembly": get_assembly(ea),
            })
        }
    """)

idc.qexit(0)
