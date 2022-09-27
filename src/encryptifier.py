"""
Some code for small encryption demo

We create some random keys and nonces so users can test a bit
"""

from base64 import b64decode, b64encode

import sys

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

keys = []
nonces = []
ciphertexts = []

def print_header():
    print("####################################################")
    print("## Encryptifier")
    print("####################################################")
    print("This program allows you to test encrypting and decrypting some data")
    print("Some random keys and nonces have been generated for you.")
    print("Note that you can only decrypt something using the exact same key and nonce used for encryption")
    print("Close all input by pressing enter.")
    print_keys_and_nonces()
    print_options()

def print_options():
    print("")
    print("Press a key and close with enter")
    print("e: encrypt something")
    print("d: decrypt something")
    print("l: list data")
    print("q: exit the application")    
    rec_input = input("What do you want to do? ")
    handle_input(rec_input)

def handle_input(rec_input):
    if rec_input == "q":
        print("Thanks for trying the demo")
        sys.exit(0)
    elif rec_input == "e":
        encrypt_something()
    elif rec_input == "d":
        decrypt_something()
    elif rec_input == "l":
        print_keys_and_nonces()
        print_ciphers()
        print_options()
    else:
        print("Unknown input, please try again")
        print_options()

def encrypt_something():
    print("Encrypting.")
    plaintext = input("What do you want to encrypt: ")
    enckey = input("Enter a number for the key you want to use (1, 2 or 3): ")
    nonce = input("Enter a number for the nonce you want to use (1, 2 or 3): ")
    try:
        enckey = int(enckey) - 1
        nonce = int(nonce) - 1
        if enckey < 0 or enckey > 2 or nonce < 0 or nonce > 2:
            print("Invalid input for enckey or nonce. Aborting.")
            print_options()    
    except ValueError:
        print("Invalid input for enckey or nonce. Aborting.")
        print_options()
    
    print("Encrypting \"{}\" with key {} and nonce {}".format(plaintext, b64encode(keys[enckey]).decode("utf-8"), b64encode(nonces[nonce]).decode("utf-8")))
    cipher = ChaCha20.new(key = keys[enckey], nonce = nonces[nonce])
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
    ciphertexts.append({"key": enckey, "nonce": nonce, "ciphertext": ciphertext})

    print_ciphers()
    print_options()    
    
def decrypt_something():
    print("Decrypting.")
    ciphernr = input("Which cipher do you want to decrypt? Enter a number with the first ciphertext being 1: ")
    enckey = input("Enter a number for the key you want to use (1, 2 or 3): ")
    nonce = input("Enter a number for the nonce you want to use (1, 2 or 3): ")
    try:
        ciphernr = int(ciphernr) - 1
        enckey = int(enckey) - 1
        nonce = int(nonce) - 1
        if enckey < 0 or enckey > 2 or nonce < 0 or nonce > 2 or ciphernr < 0 or ciphernr >= len(ciphertexts):
            print("Invalid input. Please check if the line number you are entering exists. Aborting.")
            print_options()
    except ValueError:
        print("Invalid input. Please check if the line number you are entering exists. Aborting.")
        print_options()

    print("Decrypting {} with key {} and nonce {}".format(b64encode(ciphertexts[ciphernr]["ciphertext"]).decode("utf-8"),
            b64encode(keys[enckey]).decode("utf-8"), b64encode(nonces[nonce]).decode("utf-8")))
    
    cipher = ChaCha20.new(key = keys[enckey], nonce = nonces[nonce])
    plaintext = cipher.decrypt(ciphertexts[ciphernr]["ciphertext"])
    print("The decryption result is \"{}\"".format(plaintext))
    print("Was this the original input?")
    print_options()

def generate_random_keys_and_nonces():
    keys.append(get_random_bytes(32))
    keys.append(get_random_bytes(32))
    keys.append(get_random_bytes(32))
    nonces.append(get_random_bytes(8))
    nonces.append(get_random_bytes(8))
    nonces.append(get_random_bytes(8))

def print_ciphers():
    print("")
    print("Encrypted data")
    print("{}{}{}".format("key ", "nonce ", "ciphertext"))
    for cphr in ciphertexts:
        print("{0:<4}{1:<6}{2:}".format(cphr["key"] + 1, cphr["nonce"] + 1, b64encode(cphr["ciphertext"]).decode("utf-8")))

def print_keys_and_nonces():
    print("")
    print("Available keys:")
    for i in range(0, 3):
        print("{}: {}".format(i + 1, b64encode(keys[i]).decode("utf-8")))
    print("Available nonces:")
    for i in range(0, 3):
        print("{}: {}".format(i + 1, b64encode(nonces[i]).decode("utf-8")))

if __name__ == "__main__":
    generate_random_keys_and_nonces()
    print_header()
    
