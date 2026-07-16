import json
import os
import pathlib
import re
import subprocess
import sysconfig
import time
import sys
import random

import dotenv
import humanfriendly
import tqdm

HEXRAYS_CONFIG = """

MAX_FUNCSIZE = 500000

""".strip()

# if this returns false the program should exit
def setup_stuffs() -> bool:
    user_config_dir = None
    if os.name == "nt":
        user_config_dir = pathlib.Path.home() / "AppData/Roaming/Hex-Rays/IDA Pro/cfg"
    else:
        user_config_dir = pathlib.Path.home() / ".idapro/cfg"

    hexrays_cfg_file = user_config_dir / "hexrays.cfg"
    if hexrays_cfg_file.exists():
        with open(hexrays_cfg_file) as config:
            if config.read() != HEXRAYS_CONFIG:
                print(f"Your IDA already has a user-local config file at {hexrays_cfg_file.absolute()}!")
                print(f"Please (re)move this so that custom configs can be loaded.")
                return False

        hexrays_cfg_file.unlink()

    user_config_dir.mkdir(parents=True, exist_ok=True)

    # write custom config
    with open(hexrays_cfg_file, "w") as config:
        config.write(HEXRAYS_CONFIG)

    print(f"Written custom config to {hexrays_cfg_file}, you might want to delete this afterwards!")

    # clear any half-complete databases so we dont parse them by accident
    extension_blacklist = [".id0", ".id1", ".id2", ".nam", ".til", ".$$$"]
    files = [file for file in pathlib.Path("./binaries").iterdir()]
    for file in files:
        for extension in extension_blacklist:
            if file.name.endswith(extension):
                print(f"Removing {file.name}...")
                file.unlink()

    # clear ida log
    with open(pathlib.Path("./ida.log"), "w") as log:
        log.write("")

    return True

def generate_prefix(json_data):
    ret = ""

    byte_len = json_data["end"] - json_data["start"]

    ret += "// \n"

    ret += f"// {json_data["name"]} from {hex(json_data["start"])} to {hex(json_data["end"])} ({byte_len} bytes)\n"

    ret += "// \n"

    ret += f"// {len(json_data["xrefs"])} xrefs:\n"
    for xref in json_data["xrefs"]:
        ret += f"// > {xref}\n"

    ret += "// \n"

    # TODO: make this better
    unhookable = False
    if byte_len < 16:
        ret += "// This function may be unhookable on ARM64!! (size < 16)\n"
        unhookable = True
    if byte_len < 8:
        ret += "// This function may be unhookable on ARM32!! (size < 8)\n"
        unhookable = True

    if not unhookable:
        ret += "// This function is hookable on all platforms!\n"

    ret += "// \n"

    ret += f"// Using BromaIDA {json_data["bida_info"]}\n"

    ret += "// \n"

    return ret


def write_output_files(binary_path: pathlib.Path, json_data):
    output_path = pathlib.Path(f"./output/{binary_path.name}/")
    output_path.mkdir(parents=True, exist_ok=True)

    file_safe_name: str = json_data["name"]

    # Fuck you
    if file_safe_name.endswith("operator/"):
        file_safe_name = file_safe_name[:-9] + "operator_div"

    if file_safe_name.endswith("operator*"):
        file_safe_name = file_safe_name[:-9] + "operator_mul"

    file_safe_name = re.sub(r"[?@:<>,*&~]", "_", file_safe_name)
    file_safe_name = file_safe_name[:100]

    cpp_path = output_path / (f"{file_safe_name}{".mm" if json_data["is_objc"] else ".cpp"}")
    asm_path = output_path / f"{file_safe_name}.asm"

    with open(cpp_path, "w", encoding="utf-8") as source:
        source.write(generate_prefix(json_data))
        source.write("\n")
        source.write(json_data["pseudocode"])

    with open(asm_path, "w", encoding="utf-8") as source:
        source.write(generate_prefix(json_data).replace("//", ";"))
        source.write("\n")
        source.write(json_data["assembly"])

    return json_data["name"]


# returns if the binary successfully parsed or not
def run_for_one_binary(path: pathlib.Path) -> bool:
    print(f"Running for {path.absolute()}")

    # TODO: is there a better way to do this?
    bromaida_blacklist = ["fmod.dll", "libfmod-32.so", "libfmod-64.so", "libExtensions.dll"]

    invoke_bromaida = True
    for filename in bromaida_blacklist:
        if path.name == filename:
            invoke_bromaida = False
            break

    process = subprocess.Popen(
        [
            pathlib.Path(os.environ["IDA_DIRECTORY"]).joinpath("idat"),
            "-A",  # autonomous mode
            # "-c", # re-disassemble
            "-Lida.log",  # logfile
            "-v",  # verbose
            # ida.py <cwd> <venv lib path> <invoke bromaida?>
            f'-S"{pathlib.Path("./ida.py").absolute()}" "{pathlib.Path("./").absolute()}" "{pathlib.Path(sysconfig.get_path("purelib")).absolute()}" "{"True" if invoke_bromaida else "False"}"',  # launch script
            f"{path.absolute()}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    # for type checking
    if not process.stdout:
        return False

    pbar: tqdm.tqdm | None = None

    for line in process.stdout:
        line = line.strip()
        if not line.startswith("[gdwd]"):
            continue

        line = line[6:]

        if line.startswith(">"):
            print(f"    {line[1:]}")
            continue

        try:
            line_data = json.loads(line)

            if line_data["type"] == "metadata":
                pbar = tqdm.tqdm(total=line_data["func_count"])
                continue

            if line_data["type"] == "func":
                if not pbar:
                    print("no progress bar")
                    return False

                file_name = write_output_files(path, line_data)

                bar_description = f"{file_name.ljust(80)} | Analysing {path.name}"

                pbar.set_description(bar_description)  # not really what this is meant for but it works
                pbar.update()
        except Exception as err:
            print(f"Failed to parse {line[:30]}...")
            print(err)

            random_filename = random.randbytes(5).hex().rjust(5, "0")
            print(f"Saving failed line to fail-{random_filename}.json, check that please!")
            with open(pathlib.Path(f"./fail-{random_filename}.json"), "w") as file:
                file.write(line)

            process.kill()
            return False

    process.wait()

    if pbar:
        pbar.set_description(f"Parsing {path.name}")
        pbar.close()

    return True

def run_for_binaries(binaries: list[pathlib.Path]) -> list[str]:
    extension_do_not_iter_list = [".i64", ".idb"]
    failed_files = []

    for file in binaries:
        if file.is_dir():
            continue

        if not file.exists():
            print(f"{file} does not exist!")
            continue

        do_not_parse = False
        for extension in extension_do_not_iter_list:
            if file.name.endswith(extension):
                do_not_parse = True
                break

        if do_not_parse:
            continue

        success = run_for_one_binary(file)
        if not success:
            failed_files.append(file.name)

    return failed_files

# returns the failed binary names
def run_for_all_binaries() -> list[str]:
    return run_for_binaries([file for file in pathlib.Path("./binaries").iterdir()])


if __name__ == "__main__":
    dotenv.load_dotenv()

    if not setup_stuffs():
        exit(1)

    start = time.perf_counter()

    failed_files = []

    if len(sys.argv) != 1:
        sys.argv.pop(0)
        failed_files = run_for_binaries([ pathlib.Path(f"./binaries/{file}") for file in sys.argv ])
    else:
        failed_files = run_for_all_binaries()

    end = time.perf_counter()

    print(f"Done! Took {humanfriendly.format_timespan(end - start)}!")

    if len(failed_files) > 0:
        print(f"{len(failed_files)} files failed to be parsed!")
        for file in failed_files:
            print(f" - {file}")
