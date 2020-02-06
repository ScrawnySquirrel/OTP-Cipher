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

    # dec = parser.add_mutually_exclusive_group(required='-d' or '--decrypt' in argv)
    # dec.add_argument('-k', '--key', help='the decryption key')

    enc = parser.add_mutually_exclusive_group(required='-e' or '--encrypt' or '-d' or '--decrypt' in argv)
    enc.add_argument('-t', '--text', help='the plaintext to encrypt')
    enc.add_argument('-i', '--interactive', help='interactively provide the plaintext', action='store_true')
    enc.add_argument('-f', '--file', help='name of the input file')

    parser.add_argument('-o', '--outputfile', help='name of the output text file')

    args = parser.parse_args()

    if args.encrypt is not None:
        encrypt_otp(args.text)
    elif args.decrypt is not None:
        if args.key is None:
            parser.error("error: one of the arguments -k/--key is required")
            exit()
        decrypt_otp(args.text, args.key)

def generate_key(length):
    key = [str(random.randint(0,1)) for x in range(length)]
    return "".join(key)

def xor_compare(text_bin, key_bin):
    # return bin(int(text_bin,2) ^ int(key_bin,2))[2:]
    return  '{0:0{0}b}'.format(int(text_bin,2) ^ int(key_bin, 2), len(text_bin))

def encrypt_otp(ptext):
    ptext_bin = bin(int(binascii.hexlify(ptext), 16))[2:]
    key_bin = generate_key(len(ptext_bin))
    xor_bin = xor_compare(ptext_bin,key_bin)

    print("Plaintext:\t{}".format(ptext_bin))
    print("Key:\t\t{}".format(key_bin))
    print("Ciphertext:\t{}".format(xor_bin))
    return

def decrypt_otp(ctext, key):
    ctext_bin = ctext
    key_bin = key
    xor_bin(ctext_bin, key_bin)

    print("Plaintext:\t{}".format(ptext_bin))
    print("Key:\t\t{}".format(key_bin))
    print("Ciphertext:\t{}".format(xor_bin))
    return

if __name__ == "__main__":
    main(sys.argv[1:])
