import idc
import pathlib

cwd = pathlib.Path(idc.ARGV[1])
sys.path.insert(0, idc.ARGV[2])
should_invoke_bromaida = idc.ARGV[3] == "True"

import io
import json
import os
import subprocess
import sys
import time
import zipfile

import dotenv
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idp
import ida_lines
import ida_name
import ida_pro
import idautils
import requests




def print_prefixed(message):
    os.write(1, f"\n[gdwd]{message}\n".encode())


bida_path = cwd / "./bromaida"
if not bida_path.exists():
    print_prefixed(f">Extracting BromaIDA from {os.environ["BROMA_IDA_REPO"]}@{os.environ["BROMA_IDA_BRANCH"]}...")

    res = requests.get(f"https://github.com/{os.environ["BROMA_IDA_REPO"]}/archive/refs/heads/{os.environ["BROMA_IDA_BRANCH"]}.zip")
    res.raise_for_status()

    bida_path.mkdir(exist_ok=True)

    with zipfile.ZipFile(io.BytesIO(res.content)) as zip_file:
        zip_file.extractall(bida_path)

    # since the zip has an inner folder "BromaIDA-master"
    [_, repo_name] = os.environ["BROMA_IDA_REPO"].split("/")
    inner_dir = bida_path / f"{repo_name}-{os.environ["BROMA_IDA_BRANCH"]}"
    for item in inner_dir.iterdir():
        item.rename(bida_path / item.name)

    inner_dir.rmdir()

sys.path.insert(0, str(bida_path.absolute()))

from broma_ida.broma.importer import BromaImporter
from broma_ida.data.data_manager import DataManager
from broma_ida.metadata import BROMAIDA_GITHUB, SCRIPT_VERSION
from broma_ida.utils import IDAUtils

dotenv.load_dotenv(cwd / ".env")

if not ida_hexrays.init_hexrays_plugin():
    ida_pro.qexit(0)

print_prefixed(">Waiting for IDA to do its shit...")
ida_auto.auto_wait()

if should_invoke_bromaida:
    # usage taken from bromaida
    print_prefixed(">Loading DataManager...")
    DataManager().init(bida_path / "broma_ida" / "shelf")
    DataManager().set("always_overwrite_merge_information", True)
    DataManager().set("disable_broma_hash_check", True)
    DataManager().set("always_overwrite_idb", True)
    DataManager().set("import_types", True)
    DataManager().set("set_default_parser_args", True)
    DataManager().set("ignore_mismatched_structs", True)

    # usage also taken from bromaida
    print_prefixed(">Invoking BromaImporter...")
    broma_importer = BromaImporter(IDAUtils.get_platform(), pathlib.Path(os.environ["BINDINGS_PATH"]))
    broma_importer.parse_bromas()
    broma_importer.import_into_idb()
else:
    print_prefixed(">Skipping BromaIDA for this file...")

bindings_commit_hash = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=pathlib.Path(os.environ["BINDINGS_PATH"])).strip().decode()
bindings_commit_time = time.ctime(int(subprocess.check_output(["git", "log", "-1", "--date=short", "--pretty=format:%ct"], cwd=pathlib.Path(os.environ["BINDINGS_PATH"]))))
bindings_remote = subprocess.check_output(["git", "remote", "get-url", "origin"], cwd=pathlib.Path(os.environ["BINDINGS_PATH"])).strip().decode()

def get_func_name(func_ea):
    maybe_mangled = ida_funcs.get_func_name(func_ea)

    demangled = ida_name.demangle_name(maybe_mangled, ida_name.MNG_SHORT_FORM)
    if demangled is None:
        demangled = maybe_mangled
    else:
        # remove params that demangle_name gives us (only android will go down this route since it gives us mangled names)
        demangled = demangled.split("(", 1)[0]

    return demangled


def get_pseudocode(func_ea):
    decompiled_func = ida_hexrays.decompile(func_ea)
    if decompiled_func is None:
        return "// Failed to decompile!"

    lines = []
    for sline in decompiled_func.get_pseudocode():
        line = ida_lines.tag_remove(sline.line)
        lines.append(line)

    return "\n".join(lines)


def get_assembly(func_ea):
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return None

    lines = []
    ea = func.start_ea
    while ea < func.end_ea:
        line = ida_lines.generate_disasm_line(ea, 0)
        line = ida_lines.tag_remove(line)
        if line == "":
            line = "/* (failed to disassemble line) */"

        line = f"{line.ljust(70)} ; +{hex(ea - func.start_ea)}, {hex(ea)}"
        lines.append(line)

        ea = ida_bytes.next_head(ea, func.end_ea)

    return "\n".join(lines)


def get_xrefs(func_ea):
    refs = []

    for xref in idautils.XrefsTo(func_ea):
        frm = xref.frm  # pyright: ignore[reportAttributeAccessIssue]

        caller = ida_funcs.get_func(frm)

        if caller:
            refs.append(f"{get_func_name(caller.start_ea)} @ {hex(frm)}")
        else:
            refs.append(f"<???> @ {hex(frm)}")

    return refs


func_count = sum(1 for _ in idautils.Functions())
print_prefixed(
    json.dumps(
        {
            "type": "metadata",
            "func_count": func_count,
        }
    )
    .replace("\n", "")
    .strip()
)

for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)

    demangled = get_func_name(ea)

    is_objc = demangled.startswith("-[") or demangled.startswith("+[")

    print_prefixed(
        json.dumps(
            {
                "type": "func",
                "start": func.start_ea,
                "end": func.end_ea,
                "name": demangled,
                "pseudocode": get_pseudocode(ea),
                "assembly": get_assembly(ea),
                "xrefs": get_xrefs(ea),
                "is_objc": is_objc,
                "is_arm32": ida_idp.get_idp_name() == "ARM" and ida_ida.inf_is_32bit_exactly(),
                "is_arm64": ida_idp.get_idp_name() == "ARM" and ida_ida.inf_is_64bit(),
                "bida_info": f"{SCRIPT_VERSION} @ {BROMAIDA_GITHUB}",
                "bindings_info": f"commit {bindings_commit_hash} at {bindings_commit_time} from {bindings_remote}",
            }
        )
        .replace("\n", "")
        .strip()
    )

print_prefixed(
    json.dumps(
        {
            "type": "end",
        }
    )
    .replace("\n", "")
    .strip()
)

ida_pro.qexit(0)
