import rsa
'''
Here RSA module is used to encrypt, decrypt and Sign and Verify the Encryption method. The complete code is written in Python 3.7.4 and the module used is rsa 4.0.
This code is written by: Urmil Kalaria and Pradyuman Kanan
This code is written for the course: Advance Algorithms
'''
class RSA():
    '''
    Class initialization for generating the keys and writing them to the file.
    Public Key and Private Key are protected using the standard OOP concepts.
    '''
    def __init__(self) -> None:
        self.__PublicKey, self.__PrivateKey = rsa.newkeys(1024)
        self.writeKeys()

    def writeKeys(self):
        with open('keys/publicKey.pem', 'wb') as p:
            p.write(self.__PublicKey.save_pkcs1('PEM'))
        with open('keys/privateKey.pem', 'wb') as p:
            p.write(self.__PrivateKey.save_pkcs1('PEM'))

class Encrypt(RSA):
    '''
    Class initialization for encrypting the message using the public key. The message is encrypted using the RSA module.
    Returns the encrypted message in Type: bytes.
    '''
    def __init__(self, message) -> None:
        self.message = message
        try:
            with open('keys/publicKey.pem', 'rb') as p:
                self.__publicKey = rsa.PublicKey.load_pkcs1(p.read())
            with open('keys/privateKey.pem', 'rb') as p:
                self.__privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        except:
            self.generate_keys()
            with open('keys/publicKey.pem', 'rb') as p:
                self.__publicKey = rsa.PublicKey.load_pkcs1(p.read())
    def generate_keys(self):
        RSA.__init__(self)
        RSA.writeKeys(self)
    def encrypt(self):
        return rsa.encrypt(self.message, self.__publicKey)

class Decrypt():
    '''
    Class initialization for decrypting the message using the private key. The message is decrypted using the RSA module.
    Returns the decrypted message in Type: bytes.
    '''
    def __init__(self, ciphertext) -> None:
        self.ciphertext = ciphertext
        try:
            with open('keys/privateKey.pem', 'rb') as p:
                self.__privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        except Exception as e:
            print(e)
            return False
    def decrypt(self):
        try:
            return rsa.decrypt(self.ciphertext, self.__privateKey)
        except Exception as e:
            print(e)
            return False

class Sign():
    '''
    Class initialization for signing the message using the private key. The message is signed using the RSA module.
    Returns the signed message in Type: bytes.
    Sign provids the integrity of the message by checking the digital signature of the message.
    '''
    def __init__(self, message) -> None:
        self.message = message
        try:
            with open('keys/privateKey.pem', 'rb') as p:
                self.__privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        except Exception as e:
            print(e)
        
    def sign(self):
        return rsa.sign(self.message.encode('ascii'), self.__privateKey, 'SHA-1')
    
class Verify():
    '''
    Class initialization for verifying the message using the public key. The message is verified using the RSA module.
    Returns the verified message in Type: bytes.
    Verify provids the integrity of the message by checking the digital signature of the encoded message and matches with Sign.
    '''
    def __init__(self, message, signature) -> None:
        self.message = message
        self.signature = signature
    def verify(self):
        try:
            with open('keys/publicKey.pem', 'rb') as p:
                self.__publicKey = rsa.PublicKey.load_pkcs1(p.read())
            return rsa.verify(self.message.encode('ascii'), self.signature, self.__publicKey) == 'SHA-1'
        except Exception as e:
            print(e)
            return False
