#!/usr/bin/python3.7

import sys
import argparse
import binascii
import random

def main(argv):
    # Define script description and the arugment list
    parser = argparse.ArgumentParser(description='Encrypt and decrypt a One-Time Pad Cipher.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-e', '--encrypt', help='encrypt a plaintext', action='store_true')
    mode.add_argument('-d', '--decrypt', help='decrypt a ciphertext', action='store_true')
    enc = parser.add_mutually_exclusive_group(required='-e' or '--encrypt' or '-d' or '--decrypt' in argv)
    enc.add_argument('-t', '--text', help='the plaintext to encrypt')
    enc.add_argument('-i', '--interactive', help='interactively provide the plaintext', action='store_true')
    enc.add_argument('-f', '--file', help='name of the input file')
    parser.add_argument('-k', '--key', help='the decryption key')
    # TODO: Implement output file capability
    parser.add_argument('-o', '--outputfile', help='name of the output text file')
    args = parser.parse_args()

    # Cipher variables
    txt = ""
    key = ""
    res = ""

    # Output file
    if args.outputfile is not None:
        out_file = open(args.outputfile, "w")

    # Handle different input functionality
    if args.text is not None:
        txt = args.text
    elif args.interactive is True:
        txt = input("Enter text: ")
    elif args.file is not None:
        txt = open(args.file, "r").read()

    # Handle encryption or decryption logic
    if args.encrypt is True:
        txt = string_to_binary(txt)
        key = generate_binary_key(len(txt))
        res = binary_to_hex(xor_compare(txt, key))
        print("Key: {}".format(binary_to_hex(key)))
        print("Ciphertext: {}".format(res))
        if args.outputfile is not None:
            out_file.write(res)
    elif args.decrypt is True:
        # Handle key input functionality
        if args.key is None and not key:
            parser.error("argument -k/--key is required")
            exit()
        elif args.key is not None:
            key = args.key
        elif args.interactive is True:
            key = input("Enter key: ")
        else:
            exit()
        res = binary_to_string("0b"+xor_compare(hex_to_binary(txt), hex_to_binary(key)))
        print("Plaintext: {}".format(res).rstrip())
        if args.outputfile is not None:
            out_file.write(res)

def string_to_binary(str):
    """
    Return a string converted binary.

    str - the string to convert
    """
    return bin(int(binascii.hexlify(str.encode()), 16))[2:]

def binary_to_string(bnry):
    """
    Return a binary converted string.

    bnry - the binary to convert
    """
    return binascii.unhexlify('%x' % int(bnry, 2)).decode()

def binary_to_hex(bnry):
    """
    Return a binary converted hex.

    bnry - the binary to convert
    """
    return hex(int(bnry,2))[2:]

def hex_to_binary(hexa):
    """
    Return a hex converted binary.

    hexa - the hex to convert
    """
    return bin(int(hexa, 16)).zfill(8)

def generate_binary_key(length):
    """
    Return a randomly generated binary key of size length.

    length - the length of the key to generate
    """
    key = [str(random.randint(0,1)) for x in range(length)]
    return "".join(key)

def xor_compare(bin1, bin2):
    """
    Return an XOR comparison of two binary strings.

    bin1, bin2 - the binaries to compare
    """
    return '{0:0{1}b}'.format(int(bin1,2) ^ int(bin2, 2), len(bin1))

if __name__ == "__main__":
    main(sys.argv[1:])
