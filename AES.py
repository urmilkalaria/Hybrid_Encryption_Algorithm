from Crypto.Cipher import AES

'''
AES Encryption and Decryption is a symmetric encryption technique. It uses the same key for encryption and decryption. 
This makes it vunerable to brute force attack. 
To make it more secure, we use Hybrid technique of AES and RSA to encrypt the key of AES using RSA and store it in a file. 
This makes it impossible to crack in finite amount of time.
This module is implementation of AES block cipher.
'''

def encrypt(key, msg):
    cipher = AES.new(key, AES.MODE_EAX)

    cipher_text, tag = cipher.encrypt_and_digest(msg)
    nonce = cipher.nonce

    return cipher_text, tag, nonce


def decrypt(cipher_text, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(cipher_text, tag)
    return data.decode()  
