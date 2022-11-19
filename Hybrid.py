import AES
import RSA

'''
Hybrid Encryption and Decryption is a combination of symmetric and asymmetric encryption techniques.
Central idea of this technique is to use symmetric encryption technique to encrypt the plain text and asymmetric encryption technique to encrypt the key of symmetric encryption technique.
This will reduce the computational complexity for ciphering and deciphering text and can be used in IOT devices
However security of this technique is not compromised. Infact it is more secure than symmetric lightweight encryption techniques.
'''

def encrypt(plain_text, key):
    '''
    Encrypts the plain text using AES and Key of AES using RSA and store the encrypted key in keys/AES_encryption_key.txt
    Returns the cipher text, nonce and tag of the plain text.
    This provides double protection to the plain text and makes it impossible to crack in finite amount of time.
    '''
    if not plain_text:
        return ''
    else:
        cipher = AES.encrypt(key, plain_text)
        with open("keys/AES_key.txt", "wb") as f:
            f.write(key)
        RSA.RSA()
        with open("keys/AES_encryption_key.txt", "wb") as f:
            f.write(RSA.Encrypt(key).encrypt())
    return cipher

def decrypt(cipher_text, nonce, tag):
    '''
    Decrypts the cipher text using AES and Key of AES using RSA.
    Returns the plain text or deciphered message.
    '''
    if not cipher_text:
        return ''
    else:
        with open("keys/AES_encryption_key.txt", "rb") as f:
            secret_key = f.read()
        key = RSA.Decrypt(secret_key).decrypt()
        # print(key)
        decipher = AES.decrypt(cipher_text,key,nonce,tag)
        return decipher