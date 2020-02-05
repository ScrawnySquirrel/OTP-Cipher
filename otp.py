import sys
import argparse

def main(argv):
    # Define script description and the arugment list
    parser = argparse.ArgumentParser(description='Encrypt and decrypt a One-Time Pad Cipher.')

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-e', '--encrypt', help='encrypt a plaintext', action='store_true')
    mode.add_argument('-d', '--decrypt', help='decrypt a ciphertext', action='store_true')

    input_format = parser.add_mutually_exclusive_group(required='-e' or '--encrypt' in argv)
    input_format.add_argument('-p', '--plaintext', help='the plaintext to encrypt')
    input_format.add_argument('-i', '--interactive', help='interactively provide the plaintext', action='store_true')
    input_format.add_argument('-f', '--inputfile', help='name of the input plaintext file')

    parser.add_argument('-o', '--outputfile', help='name of the output text file')

    args = parser.parse_args()

if __name__ == "__main__":
    main(sys.argv[1:])
