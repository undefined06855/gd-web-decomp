import json
import os
import pathlib
import subprocess
import sysconfig
import time

import dotenv
import humanfriendly
import jsonpickle
import tqdm


class BinaryFunction:
    def __init__(self, json_data):
        self.start: int = json_data["start"]
        self.end: int = json_data["end"]
        self.name: str = json_data["name"]
        self.psuedocode: str = json_data["pseudocode"]
        self.assembly: str = json_data["assembly"]


class Binary:
    def __init__(self, path: pathlib.Path):
        self.name = path.name
        self.functions: list[BinaryFunction] = []


def run_for_one_binary(path: pathlib.Path) -> Binary | None:
    print(f"Running for {path.absolute()}")

    # TODO: is there a better way to do this?
    bromaida_blacklist = [
        "fmod.dll",
        "libfmod-32.so",
        "libfmod-64.so",
    ]

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
            "-v", # verbose
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
        return None

    res = Binary(path)

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
                return None

            res.functions.append(BinaryFunction(json.loads(line)))
            pbar.update()
        except json.decoder.JSONDecodeError:
            print(f"Failed to parse json: {line}")
            break
        except ValueError:
            print(f"Failed to parse string: {line}")
            break

    process.wait()

    for line in process.stderr:
        line = line.strip()
        if line == "":
            continue

        print("Error from IDA:")
        print("\n    ".join(process.stderr.readlines()))
        return None

    return res


def run_for_all_binaries() -> str:
    output: dict[str, Binary] = {}

    extension_blacklist = [ ".id0", ".id1", ".id2", ".nam", ".til", "$$$", ".i64", ".idb" ]

    for file in pathlib.Path("./binaries").iterdir():
        for extension in extension_blacklist:
            if file.name.endswith(extension):
                print(f"Removing {file.name}...")
                file.unlink()

    # clear ida log
    with open(pathlib.Path("./ida.log"), "w") as log:
        log.write("")

    for file in pathlib.Path("./binaries").iterdir():
        if file.is_dir():
            continue

        res = run_for_one_binary(file)
        if not res:
            return "{}"

        output[file.name] = res

    dump = jsonpickle.dumps(output, unpicklable=True)
    if type(dump) != str:
        print("failed to json-ify")
        return "{}"

    return dump


if __name__ == "__main__":
    dotenv.load_dotenv()

    start = time.perf_counter()

    with open(pathlib.Path("./output.json"), "w") as output:
        output.write(run_for_all_binaries())

    end = time.perf_counter()

    print(f"Done! Took {humanfriendly.format_timespan(end - start)}!")
