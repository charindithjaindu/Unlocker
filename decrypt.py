#!/usr/bin/env python3
import os,time,zlib,base64
from time import sleep
'''
Copyright (C) Razor Kenway (SL Android )
Dont modify Or edit
'''
print("\033[1;32;40m _   _ _   _ _     ___   ____ _  _______ ____")
print("\033[1;32;40m| | | | \ | | |   / _ \ / ___| |/ / ____|  _ \ ")
print("\033[1;32;40m| | | |  \| | |  | | | | |   |   /|  _| | |_) |   ")
print("\033[1;32;40m| |_| | |\  | |__| |_| | |___| . \| |___|  _ < ")
print(" \033[1;31;40m\___/|_| \_|_____\___/ \____|_|\_\_____|_| \_\ ")
print("")
print("\033[1;33m                              Tool By Razor Kenway ")
print("\033[1;33m                                     SL Android  ")
print("")
print("\033[1;31;40m Decryptor for TunnelTweak, SocksHTTP")
print("\033[1;31;40m and TunnelMate configuration files.")
print("\033[1;31;40m Easily decrypt files")
print("\033[1;31;40m with .tut, .tmt and .sks extension! ")
print("")
print("\033[1;32;40m NOW TYPE : python3 decrypt.py <file name> ")
time.sleep(0.2)
os.system("termux-open-url https://www.youtube.com/c/SLAndroid")

from sys import stdin, stdout, stderr

from argparse import ArgumentParser
from pathlib import Path

from base64 import b64decode

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

DEFAULT_FILE_EXTENSION = '.tmt'

# passwords to derive the key from
PASSWORDS = {
    '.tut': b'fubvx788b46v',
    '.sks': b'dyv35224nossas!!',
    '.tmt': b'fubvx788B4mev',
}

# some utility functions
def error(error_msg = 'Corrupted/unsupported file.'):
    stderr.write(f'\033[41m\033[30m X \033[0m {error_msg}\n')
    stderr.flush()

    exit(1)

def warn(warn_msg):
    stderr.write(f'\033[43m\033[30m ! \033[0m {warn_msg}\n')
    stderr.flush()

def ask(prompt):
    stderr.write(f'\033[104m\033[30m ? \033[0m {prompt} ')
    stderr.flush()

    return input()

def human_bool_to_bool(human_bool):
    return 'y' in human_bool

def main():
    # parse arguments
    parser = ArgumentParser()
    parser.add_argument('file', help='file to decrypt')

    output_args = parser.add_mutually_exclusive_group()
    output_args.add_argument('--output', '-o', help='file to output to')
    output_args.add_argument('--stdout', '-O', action='store_true', help='output to stdout', default=True)

    args = parser.parse_args()

    # open file
    encrypted_contents = open(args.file, 'r').read()

    # determine the file's extension
    file_ext = Path(args.file).suffix
    
    if file_ext not in PASSWORDS:
        warn(f'Unknown file extension, defaulting to {DEFAULT_FILE_EXTENSION}')
        file_ext = DEFAULT_FILE_EXTENSION

    # split the file
    split_base64_contents = encrypted_contents.split('.')

    if len(split_base64_contents) != 3:
        raise ValueError('Unsupported file.')

    split_contents = list(map(b64decode, split_base64_contents))

    # derive the key
    decryption_key = PBKDF2(PASSWORDS[file_ext], split_contents[0], hmac_hash_module=SHA256)

    # decrypt the file
    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
    decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])

    # decide where to write contents
    if args.output:
        output_file_path = Path(args.output)

        # check if the file exists
        if output_file_path.exists() and output_file_path.is_file():
            # check if the user agrees to overwrite it
            if not human_bool_to_bool(ask(f'A file named "{args.output}" already exists. Overwrite it? (y/n)')):
                # if user doesn't, quit
                exit(0)
        
        # write the contents to the file
        output_file = open(output_file_path, 'wb')
        output_file.write(decrypted_contents)
    elif args.stdout:
        # convert the config to UTF-8
        config = decrypted_contents.decode('utf-8')

        # write it to stdout
        stdout.write(config)
        stdout.flush()

if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        error(err)
