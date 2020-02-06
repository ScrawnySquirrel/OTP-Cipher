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

    # TODO: Implement interactive and input file functionality
    enc = parser.add_mutually_exclusive_group(required='-e' or '--encrypt' or '-d' or '--decrypt' in argv)
    enc.add_argument('-t', '--text', help='the plaintext to encrypt')
    enc.add_argument('-i', '--interactive', help='interactively provide the plaintext', action='store_true')
    enc.add_argument('-f', '--file', help='name of the input file')

    parser.add_argument('-k', '--key', help='the decryption key')

    # TODO: Implemtn output file capability
    parser.add_argument('-o', '--outputfile', help='name of the output text file')

    # Execute encryption or decryption logic
    args = parser.parse_args()
    if args.encrypt is True:
        encrypt_otp(args.text)
    elif args.decrypt is True:
        if args.key is None:
            parser.error("argument -k/--key is required")
            exit()
        decrypt_otp(args.text, args.key)

def generate_key(length):
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

def encrypt_otp(ptext):
    """
    Convert plaintext to its binary equivalent (without binary literal), get a random binary key, and perform XOR comparison.

    ptext - the plaintext to encrypt
    """
    ptext_bin = bin(int(binascii.hexlify(ptext), 16))[2:]
    key_bin = generate_key(len(ptext_bin))
    xor_bin = xor_compare(ptext_bin,key_bin)

    print("Plaintext:\t{}".format(ptext_bin))
    print("Key:\t\t{}".format(key_bin))
    print("Ciphertext:\t{}".format(xor_bin))
    return

def decrypt_otp(ctext, key):
    """
    Perform XOR comparison using provided ciphertext and key. Display the resultin ASCII.

    ctext - the ciphertext in binary
    key - the key in binary
    """
    ctext_bin = ctext
    key_bin = key
    res = binascii.unhexlify('%x' % int("0b"+xor_compare(ctext_bin,key_bin), 2))

    print("Ciphertext:\t{}".format(ctext_bin))
    print("Key:\t\t{}".format(key_bin))
    print("Plaintext:\t{}".format(res))
    return

if __name__ == "__main__":
    main(sys.argv[1:])
