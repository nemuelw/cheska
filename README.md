<h1 align="center">Cheska</h1>

<p align="center">Builder for analysis-aware Windows droppers</p>

## DISCLAIMER

> This project is intended solely for educational and ethical research purposes, such as testing detection
> systems or studying malware behavior in a controlled environment. The author disclaims any liability for
> misuse.

## RESPONSIBLE USE

> Cheska is intended for red teamers, researchers, and malware analysts operating within legal boundaries and
> in controlled, consented environments. Unauthorized deployment or use against systems you do not own or have
> explicit permission to test is illegal.

## Requirements

- [Python 3](https://www.python.org/downloads)
- MinGW-w64 (`sudo apt install mingw-w64`)

## How it works

Cheska is a builder for analysis-aware Windows droppers. All the user has to provide is the payload file and
an optional output path where the resulting dropper will be saved.

When executed, the build script does the following in a nutshell:
- validates that the provided payload is a valid Windows PE executable.
- generates a random 3-character key used to XOR encode the payload and strings in the stub (e.g. DLL names).
- generates a random 3-5-character string to be used as the resource name for the encoded payload.
- configures the stub with the key and now encoded string values.
- compiles the stub and embeds the encoded payload as a resource.

The dropper, upon execution, does the following:

- Performs anti-analysis checks (detailed below)
- Loads and decodes the payload from the resources section
- Drops and executes the payload

### Anti-Analysis Techniques

| Category       | Technique                   | Description                                           |
|----------------|-----------------------------|-------------------------------------------------------|
| Anti-debugging | Unhandled exception filter  | Detects attached debugger via custom exception logic. |
| Anti-sandbox   | Mouse presence check        | Detects whether a mouse device is installed.          |
|                | Number of processors (<=2)  | Flags limited CPU environments.                       |
|                | RAM size (<2GB)             | Detects low-memory VMs or sandboxes.                  |
| Anti-VM        | Virtualization feature flag | Uses PF_VIRTUALIZATION_ENABLED to detect VT-x/AMD-V.  |
|                | Native VHD boot check       | Detects OS booted from VHD, common in VMs/sandboxes.  |
 
### Additional Defense Evasion Techniques

To further minimize detection and complicate analysis, the stub also employs:

- **PEB walking** for stealthy module enumeration
- **Dynamic API resolution** to bypass static import detection
- **String obfuscation** (e.g. XOR-encoded DLL and function names)


## Setup

> The builder was developed and tested on a Linux environment, leveraging MinGW-w64 for cross-compiling
> Windows binaries.

- Clone this repository

```bash
git clone https://github.com/nemuelw/cheska.git
```

- Navigate to the project directory
- Create a virtual environment and activate it

```bash
python3 -m venv .venv
```

```bash
. .venv/bin/activate
```

- Install project dependencies
  
```bash
pip3 install -r requirements.txt
```

## Usage

```bash
python3 cheska.py -p <PAYLOAD_FILE> [-o <OUTPUT_FILE>]
```

## Contribution

Contributions are welcome! Ideas for improvement include:

- Better anti-VM techniques (e.g. VM driver or MAC address checks)
- Additional anti-sandbox methods
- Stub optimization or improved evasion heuristics

Feel free to open an issue for discussion or submit a pull request.

## Developers & Maintainers

- Nemuel Wainaina ([nemuelwainaina@proton.me](mailto:nemuelwainaina@proton.me))
