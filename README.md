# GD Web Decomp

An online viewer for Geometry Dash's decompiled source code. Requires IDA Pro to run.

## Setup

1. *Obtain* IDA Pro (cannot be Home edition)
1. Clone the repository
1. Create a venv:
    - On Linux, run `python3 -m venv venv && source venv/bin/activate`
    - On Windows, run `python -m venv venv ; venv/Scripts/Activate`
1. Run `pip install -r requirements.txt`
1. Create a `.env` file based on the following:
    ```
    IDA_DIRECTORY=/path/to/ida
    BROMA_IDA_REPO=Stazzical/BromaIDA
    BROMA_IDA_BRANCH=master
    BINDINGS_PATH=/your/bindings/directory/bindings/2.2081
    ```
    (or just set the environment variables)
1. Create a binaries/ directory, and place your binaries into it (if you are in the Geode SDK server, check [Own The Libs](https://discord.com/channels/911701438269386882/1463361744788525080))
1. If you are running this headlessly only and have never started IDA before, you may have to provide a virtual X server
    to be able to accept the license agreement!
1. Run `generate.py`, then wait. Quite a long time. (my 5900X takes around half an hour per binary, so five hours for ten binaries!)
1. See https://github.com/undefined06855/gd-web-decomp-web for hosting the UI!

(You can also pass names of binaries to analyse individual binaries, for testing, e.g. `python generate.py GeometryJump GeometryDash.exe "Geometry Dash"`)

## Contributing

Install development packages by running `pip install -r requirements_dev.txt`

Before committing, make sure to run
```
black . -t py314 -l 120
isort .
```

And if you want to add more packages, make sure to run
```
pip-compile --strip-extras
# or
pip-compile requirements_dev.in --strip-extras
```
(ideally using python 3.14 but whatever I don't really care if it's newer)
