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
1. Run `generate.py`, then wait. Quite a long time. (each binary takes around 10 to 20 minutes on my 5900X)
1. Run `bun i` to install packages, and `bun serve` to run the server!

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
