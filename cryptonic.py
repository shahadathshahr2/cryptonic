#!/usr/bin/python3

#imports
import argparse
from pwn import *
import sys
from clint.textui import colored, puts, indent
from cryptography.fernet import Fernet
import cryptography
import time

#version

version = 'Final Release'

def keygen(kN):
    '''
    Generating and saving Key file.
    '''
    p = log.progress('Progress')

    p.status('Generating Key')
    time.sleep(2)
    key = Fernet.generate_key()
    p.success('Key successfully generated')

    q = log.progress('Progress')

    q.status('Saving Key')
    time.sleep(2)
    file = open(f'keys/{kN}', 'wb')
    file.write(key)
    file.close()
    q.success(f'Key successfully saved to: keys/{kN}')
    sys.exit(1)

def encryptText(kF, eT):
    '''
    Encrypting plain text.
    '''
    p = log.progress('Progress')

    p.status('Verifying key file')
    time.sleep(2)
    
    try:
        k = open(f'{kF}', 'rb')
        key = k.read()
        k.close()
    except FileNotFoundError:
        p.failure('Key file not found')
        sys.exit(1)

    try:
        f = Fernet(key)
        p.success('Key file successfully verified')

        q = log.progress('Progress')

        q.status('Encrypting plain text')
        time.sleep(2)
        encryptedText = f.encrypt(eT).decode()
        q.success('Plain text successfully encrypted and showing below')
        puts(colored.cyan(f'\n{encryptedText}\n'))
        sys.exit(1)

    except ValueError:
        p.failure('Key file is not verified')
        sys.exit(1)

def decryptText(kF, dT):
    '''
    Decrypting encrypted text.
    '''
    p = log.progress('Progress')

    p.status('Verifying key file')
    time.sleep(2)

    try:
        k = open(f'{kF}', 'rb')
        key = k.read()
        k.close()
    except FileNotFoundError:
        p.failure('Key file not found')
        sys.exit(1)

    try:
        f = Fernet(key)
        p.success('Key file successfully verified')

        q = log.progress('Progress')

        q.status('Decrypting encrypted text')
        time.sleep(2)
        decryptedText = f.decrypt(dT).decode()
        q.success('Encrypted text successfully decrypted and showing below')
        puts(colored.cyan(f'\n{decryptedText}\n'))
        sys.exit(1)

    except ValueError:
        p.failure('Key file is not verified')
        sys.exit(1)

    except cryptography.fernet.InvalidToken:
        q.failure('This encrypted text is not verified by this key')
        sys.exit(1)

def encryptFile(kF, eF):
    '''
    Encrypting file.
    '''
    p = log.progress('Progress')

    p.status('Verifying key file')
    time.sleep(2)

    try:
        k = open(f'{kF}', 'rb')
        key = k.read()
        k.close()
    except FileNotFoundError:
        p.failure('Key file not found')
        sys.exit(1)

    try:
        f = Fernet(key)
        p.success('Key file successfully verified')

        q = log.progress('Progress')

        q.status('Reading file')
        time.sleep(2)
        file = open(f'{eF}', 'rb')
        content = file.read()
        file.close()
        q.status('Encrypting file')
        time.sleep(2)
        encryptedContent = f.encrypt(content)
        encryptedFile = open(f'{eF}', 'wb')
        encryptedFile.write(encryptedContent)
        encryptedFile.close()
        q.success('File successfully encrypted')
        sys.exit(1)

    except ValueError:
        p.failure('Key file is not verified')
        sys.exit(1)

    except FileNotFoundError:
        q.failure('File not found')
        sys.exit(1)

def decryptFile(kF, dF):
    '''
    Decrypting encrypted text.
    '''
    p = log.progress('Progress')

    p.status('Verifying key file')
    time.sleep(2)

    try:
        k = open(f'{kF}', 'rb')
        key = k.read()
        k.close()
    except FileNotFoundError:
        p.failure('Key file not found')
        sys.exit(1)

    try:
        f = Fernet(key)
        p.success('Key file successfully verified')

        q = log.progress('Progress')

        q.status('Reading file')
        time.sleep(2)
        file = open(f'{dF}', 'rb')
        content = file.read()
        file.close()
        q.status('Decrypting file')
        time.sleep(2)
        decryptedContent = f.decrypt(content)
        decryptedFile = open(f'{dF}', 'wb')
        decryptedFile.write(decryptedContent)
        decryptedFile.close()
        q.success('File successfully decrypted')
        sys.exit(1)

    except ValueError:
        p.failure('Key file is not verified')
        sys.exit(1)

    except cryptography.fernet.InvalidToken:
        q.failure('This encrypted file is not verified by this key')
        sys.exit(1)

    except FileNotFoundError:
        q.failure('File not found')
        sys.exit(1)

def arguments():
        global parser
        parser = argparse.ArgumentParser(
            description='A tool writen in Python3 for encrypting/decrypting text/file using a randomly generated unique key.\nThe key used to encrypt the text/file will need for decrypt the text/file.',
            usage='python3 %(prog)s -kN demo',
            epilog='Example: python3 %(prog)s -kF \'keys/demo\' [-eT/-dT/-eF/-dF] [text/file]'
            )

        parser.add_argument(
            '-kN',
            help='The file name for generated key',
            metavar='Key name',
            dest='kN',
            nargs=1
            )

        parser.add_argument(
            '-kF',
            help='The key file to encrypt/decrypt (in quotes)',
            metavar='Key location',
            dest='kF',
            nargs=1
            )

        parser.add_argument(
            '-eT',
            help='The text to encrypt (in quotes)',
            metavar='Text to encrypt',
            dest='eT',
            nargs=1
            )

        parser.add_argument(
            '-eF',
            help='The file to encrypt (in quotes)',
            metavar='File to encrypt',
            dest='eF',
            nargs=1
            )

        parser.add_argument(
            '-dT',
            help='The text to decrypt (in quotes)',
            metavar='Text to decrypt',
            dest='dT',
            nargs=1
            )

        parser.add_argument(
            '-dF',
            help='The file to decrypt (in quotes)',
            metavar='File to decrypt',
            dest='dF',
            nargs=1
            )

        parser.add_argument(
            '-v', '--version',
            help='Installed version of this project',
            action='version',
            version=f'%(prog)s {version}'
            )

        global args
        args = parser.parse_args()

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

if __name__ == '__main__':
    arguments()
    if args.kN:
        keygen(args.kN[0])
        sys.exit(1)
    if args.eT:
        try:
            encryptText(args.kF[0], args.eT[0].encode())
            sys.exit(1)
        except TypeError:
            parser.print_help()
            sys.exit(1)
    if args.dT:
        try:
            decryptText(args.kF[0], args.dT[0].encode())
            sys.exit(1)
        except TypeError:
            parser.print_help()
            sys.exit(1)
    if args.eF:
        try:
            encryptFile(args.kF[0], args.eF[0])
            sys.exit(1)
        except TypeError:
            parser.print_help()
            sys.exit(1)
    if args.dF:
        try:
            decryptFile(args.kF[0], args.dF[0])
            sys.exit(1)
        except TypeError:
            parser.print_help()
            sys.exit(1)