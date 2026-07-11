import json
import os
import pathlib
import re
import subprocess
import sysconfig
import time

import dotenv
import humanfriendly
import tqdm


def generate_prefix(json_data):
    ret = ""

    ret += "// \n"

    ret += f"// {json_data["name"]} from {hex(json_data["start"])} to {hex(json_data["end"])} ({json_data["end"] - json_data["start"]} bytes)\n"

    ret += "// \n"

    ret += f"// {len(json_data["xrefs"])} xrefs:\n"
    for xref in json_data["xrefs"]:
        ret += f"// > {xref}\n"

    ret += "// \n"

    return ret


def write_output_files(binary_path: pathlib.Path, json_data):
    output_path = pathlib.Path(f"./output/{binary_path.name}/")
    output_path.mkdir(parents=True, exist_ok=True)

    file_safe_name: str = json_data["name"]
    file_safe_name = re.sub(r"[?@:<>,*&~]", "_", file_safe_name)
    file_safe_name = file_safe_name[:100]

    cpp_path = output_path / f"{file_safe_name}.cpp"
    asm_path = output_path / f"{file_safe_name}.asm"

    with open(cpp_path, "w") as source:
        source.write(generate_prefix(json_data))
        source.write("\n")
        source.write(json_data["pseudocode"])

    with open(asm_path, "w") as source:
        source.write(generate_prefix(json_data).replace("//", ";"))
        source.write("\n")
        source.write(json_data["assembly"])

    return json_data["name"]


def run_for_one_binary(path: pathlib.Path):
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
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # for type checking
    if not process.stdout or not process.stderr:
        return

    is_first_line = True
    pbar: tqdm.tqdm | None = None

    for line in process.stdout:
        line = line.strip()
        if not line.startswith("!~~"):
            continue

        line = line.lstrip("!~")

        try:
            if is_first_line:
                is_first_line = False
                pbar = tqdm.tqdm(total=int(line))
                continue

            if not pbar:
                print("no progress bar")
                return

            file_name = write_output_files(path, json.loads(line))

            pbar.update()
            pbar.set_description(f"Parsed {file_name}") # not really what this is meant for but it works
        except json.decoder.JSONDecodeError:
            print(f"Failed to parse json: {line}")
            break
        except ValueError:
            print(f"Failed to parse string: {line}")
            break

    process.wait()

    if pbar:
        pbar.set_description(f"Parsing {path.name}")
        pbar.close()

    # for line in process.stderr:
    #     line = line.strip()
    #     if line == "":
    #         continue

    #     print("Error from IDA:")
    #     print("\n    ".join(process.stderr.readlines()))
    #     return None


def run_for_all_binaries():
    # clear any ida databases or half-complete databases so we dont parse them by accident
    extension_blacklist = [".id0", ".id1", ".id2", ".nam", ".til", ".$$$", ".i64", ".idb"]
    for file in pathlib.Path("./binaries").iterdir():
        for extension in extension_blacklist:
            if file.name.endswith(extension):
                print(f"Removing {file.name}...")
                file.unlink()

    # clear ida log
    with open(pathlib.Path("./ida.log"), "w") as log:
        log.write("")

    files = [file for file in pathlib.Path("./binaries").iterdir()]
    for file in files:
        if file.is_dir():
            continue

        run_for_one_binary(file)


if __name__ == "__main__":
    dotenv.load_dotenv()

    start = time.perf_counter()

    run_for_all_binaries()

    end = time.perf_counter()

    print(f"Done! Took {humanfriendly.format_timespan(end - start)}!")
