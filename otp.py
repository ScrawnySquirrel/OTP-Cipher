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
    parser.add_argument('-o', '--outputfile', help='name of the output text file')
    args = parser.parse_args()

    # Cipher variables
    txt = ""
    key = ""
    res = ""
    out_file = None

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
        key = generate_binary_key(len(string_to_binary(txt)))
        res = otp_encrypt(txt, key)
        output_fp("Key: {}".format(binary_to_hex(key)), out_file)
        output_fp("Ciphertext: {}".format(res, out_file))
    elif args.decrypt is True:
        # Handle key input functionality
        if args.key is not None:
            key = args.key
        elif args.interactive is True:
            key = input("Enter key: ")
        else:
            parser.error("argument -k/--key is required")
            exit()
        res = otp_decrypt(txt, key)
        output_fp("Plaintext: {}".format(res, out_file))

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

def output_fp(msg, ofile = None, fp_out = False):
    """
    Print to standard out or to file.

    msg - the messsage to output
    ofile - file to output
    fp_out - output to both
    """
    if ofile is None:
        print(msg)
    else:
        ofile.write(msg + "\n")
        if fp_out is True:
            print(msg)
    return

def otp_encrypt(pt, key):
    """
    Encrypt the plaintext using the OTP cipher and a randomly generated key.
    Take string and return encrypted hex.

    pt - the plaintext
    key - the encryption key
    """
    txt = string_to_binary(pt)
    res = binary_to_hex(xor_compare(txt, key))
    return res

def otp_decrypt(ct, key):
    """
    Decrypt the ciphertext using the OTP cipher and the provided key.
    Take encrypted hex and return string

    ct - the ciphertext
    key - the decryption key
    """
    res = binary_to_string("0b"+xor_compare(hex_to_binary(ct), hex_to_binary(key)))
    return res

if __name__ == "__main__":
    main(sys.argv[1:])
