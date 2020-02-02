#!/usr/bin/python

import base64, os
import readline, glob
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt(rsa_key, filename):
    #generate and initialize a fernet Key
    key = Fernet.generate_key()
    fernet = Fernet(key)
    #Encrypt the fernet key with using public RSA key
    encrypted_key = encrypt_asymmetric(rsa_key, key)

    with open(filename, "rb") as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)

    #Write Fernet Key to first 256 bytes of file
    with open(filename, "wb") as f:
        f.write(encrypted_key)
        f.write(encrypted_data)
    return True

def decrypt(rsa_key, filename):
    #Reading Encrypted File
    with open(filename, "rb") as f:
        data = f.read()

    #Fernet Key is stored in the first 256 bytes of
    # the encrypted file
    enc_key = data[:256]
    content = data[256:]

    #decrypting Fernet key with private RSA Key
    key = decrypt_asymmetric(rsa_key, enc_key)
    fernet = Fernet(key)
    decrypted_content = fernet.decrypt(content)
    with open(filename, "wb") as f:
        f.write(decrypted_content)
    return True

def read_private_key(filename):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def read_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_asymmetric(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_asymmetric(private_key, data):
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", 'wb') as file:
        file.write(pem)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", 'wb') as file:
        file.write(pem)

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Asymmetric File Encryptor")

    parser.add_argument("-f", "--file",action="store", help="File to encrypt/decrypt")
    parser.add_argument("-k", "--key",action="store", 
    					help="Specify RSA Public Key for Encryption and RSA Private for Decryption")
    parser.add_argument("-g", "--generate-keys", dest="generate_key", action="store_true",
                        help="Whether to generate a new key or use existing")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Whether to encrypt the file, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Whether to decrypt the file, only -e or -d can be specified.")

    args = parser.parse_args()

    if args.generate_key:
        generate_keys()
        print("Generated Keys in Current Directory")
        exit()
    if args.file != None:
        if args.encrypt: 
            if args.key != None:
                rsa_public = read_public_key(args.key)
            else:
                raise Exception("Specify Public RSA Key in order to encrypt")
                exit()
            encrypt(rsa_public, args.file)
        elif args.decrypt:
            if args.key != None:
                rsa_private = read_private_key(args.key)
            else:
                raise Exception("Specify Private RSA Key in order to encrypt")
                exit()
            decrypt(rsa_private, args.file)
    else:
        raise Exception("Specify File to Encrypt")
        exit()



if __name__ == "__main__":
    main()



