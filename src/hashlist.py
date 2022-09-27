"""
Terminal application that asks for usernames and passwords 
Stores the passwords as hashes.
Try to validate based on hash
"""

import os
from re import U
import sys
import hashlib

users = {}

def print_options():
    print("")
    print("Press a key and close with enter")
    print("a: add a user")
    print("v: validate a user")
    print("l: list users")
    print("q: exit the application")    
    rec_input = input("What do you want to do? ")
    handle_input(rec_input)

def print_users():
    print("")
    print("Current users")
    print("{}{}".format("username".ljust(20), "hashcode"))
    if len(users) >= 1:
        for username in users.keys():
            print("{}{}".format(username.ljust(20), users[username]))

def handle_input(rec_input):
    if rec_input == "q":
        print("Thanks for trying the demo")
        sys.exit(0)
    elif rec_input == "a":
        add_user()
    elif rec_input == "v":
        validate_user()
    elif rec_input == "l":
        print_users()
        print_options()
    else:
        print("Unknown input, please try again")
        print_options()

def add_user():
    print("Adding user.")
    username = input("Please enter username, end with enter: ")
    if username in users:
        print("User already exists. Aborting.")
        print_options()
    else:
        password = input("Please provide a password, end with enter: ")
        print("Adding user {}, with hash of password {}".format(username, password))
        users[username] = hashlib.sha256(password.encode("utf-8")).hexdigest()
        print_users()
        print_options()

def validate_user():
    print("Validating user")
    username = input("Please provide username, end with enter: ")
    if username not in users:
        print("User does not exist. Aborting.")
        print_options()
    else:
        print("User found. Checking hash: {}".format(users[username]))
        password = input("Please enter password, end with enter: ")
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        print("Hash of entered password: {}".format(password_hash))
        if password_hash == users[username]:
            print("Hashes match! Same password used.")
        else:
            print("Hashes do not match! WE ARE BEING HACKED")
        print_options()


def print_header():
    print("#########################################################")
    print("## Hash demo")
    print("#########################################################")

if __name__ == "__main__":
    print_header()
    print_options()