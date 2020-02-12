# OTP-Cipher

Program to encrypt and decrypt using a One Time Pad.
During encryption, a random key of plaintext size is generated.

## Getting Started

These instruction will help encrypt a plaintext using a randomly generated key and decrypt ciphertext using the OTP cipher.

## Prerequisite

* Python3

## Usage
### Arguments
* `-e, --encrypt`
* `-d, --decrypt`
* `-t, --text`
* `-i, --interactive`
* `-f, --file`
* `-k, --key`
* `-o, --outputfile`

#### Cipher Operations
The program allows both the encryption and the decryption using the One Time Pad cipher.

##### Encrypt
The encryption operation (enabled by `-e`) takes in a plaintext as a string and performs the encryption operation to return the key used and the ciphertext in hex.
```
python3 otp.py -e -t "hello world"
Key: 4285d55a64625b52875a80
Ciphertext: 2ae0b9360b422c3df536e4
```

##### Decrypt
Oppose to the encryption operation, the ciphertext encrypted using the One Time Pad can be decrypted using `-d`. It takes a ciphertext and the key to return the decrypted plaintext.
```
python3 otp.py -d -t 2ae0b9360b422c3df536e4 -k 4285d55a64625b52875a80
Plaintext: hello world
```

#### Input Methods
The program allows multiple methods of inputting the plaintext/ciphertext.
> Only one input method is allowed per operation.

##### Text (Command-line)
The plaintext/ciphertext can be inputted using the `-t` argument.
```
python3 otp.py -e -t "hello world"
```
> Plaintext/ciphertext with spaces or special character must be wrapped in quotes.

##### Interactive
For usability, the plaintext/ciphertext can be inputted interactively using the `-i` argument.
```
python3 otp.py -e -i
Enter text: hello world
```
> For decryption operation, interactive method will prompt the user for the key in addition to the text.

##### File
Larger plaintext/ciphertext might not be best passing via the command-line. Alternatively, the plaintext/ciphertext can be stored in a file and inputted by providing the filename with `-f`.
```
python3 otp.py -e -f plaintext.txt
```
> The input file must only contain the plaintext or ciphertext.
>> The output file generated via `-o` while using encryption or decryption can't be passed to its opposing operation as is.
> The generated output file will have mapping which will not be handled by the program.

#### Decryption Key
During encryption, a random key with the same size of the plaintext is generated. In order to decrypt the ciphertext, the generated key must be provided.
When using the decrypt operation with either `-t` or `-f`, the key must be provided using `-k`.
```
python3 otp.py -d -t 2ae0b9360b422c3df536e4 -k 4285d55a64625b52875a80
```
> The `-k` argument is optional for `-i`. If `-k` is not provided, the program will ask for the key during its execution.

#### Output Results to File
The `-o` argument allows the output of the program to be saved to a text file.
```
python3 otp.py -e -t "hello world" -o output.txt
```

## Running the tests

## Author

**Gabriel Lee** - [ScrawnySquirrel](https://github.com/ScrawnySquirrel)
