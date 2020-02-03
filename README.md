
# Asymmetric File Encryption

This script is a demonstration of how to use RSA and Fernet to encrypt files. For performance reasons this script uses fernet, a symmetric encryption standard, to encrypt the contents of the file and then RSA to encrypt the key that fernet uses to encrypt the file. Public key cryptography is computationally expensive so this way of encrypting files is a better practice. 

## Requirements

Install cryptography library
```pip install cryptography```

## Usage

```python file_encryptor.py [-h] [-f FILE] [-k KEY] [-g] [-e] [-d]```

### Arguments
* ``-f`` or ``--file`` 
	* Specify the file you want to encrypt or decrypt
* ``-k`` or ``--key``
	* RSA key
	* Public Key for encrpytion 
	* Private Key for decryption 
* ``-g`` 
	* Generate RSA Keys if you do not already have them
* ``-e`` 
	* Specify that you want to encrypt
* ``-d``
	* Specify that you want to decrypt

### Example

File Encryption:
```python file_encryptor.py -e -f file.txt -k public_key.pem```

File Decryption:
```python file_encryptor.py -d -f file.txt -k private_key.pem```