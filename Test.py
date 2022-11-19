import Hybrid
from Crypto.Random import get_random_bytes
import timeit
import RSA
import AES
import sys

'''
This is a Test File to test the Running of Algorithm and Time taken by each Algorithm to Encrypt and Decrypt a file.
'''

def main():
    file = sys.argv[1]
    hybrid_test(file)
    rsa_test(file)
    aes_test(file)
    return 0

def hybrid_test(file):
    t0 = timeit.default_timer()
    key = get_random_bytes(16)
    t1 = timeit.default_timer()

    t2 = timeit.default_timer()
    with open(file, 'r') as f:
        msg = f.read()
    cipher = Hybrid.encrypt(key=key, plain_text=msg.encode())
    with open('Encrypted.txt', 'w') as f:
        f.write(str(cipher[0]))
    t3 = timeit.default_timer()

    t4 = timeit.default_timer()
    decipher = Hybrid.decrypt(cipher[0], cipher[2], cipher[1])
    with open('Decrypted.txt', 'w') as f:
        f.write(decipher)
    t5 = timeit.default_timer()

    print("Hybrid Key Generation Time: ", t1-t0)
    print("Hybrid Encryption Time: ", t3-t2)
    print("Hybrid Decryption Time: ", t5-t4)

def rsa_test(file):
    t0 = timeit.default_timer()
    RSA.RSA()
    t1 = timeit.default_timer()

    e_time = 0
    d_time = 0
    with open(file, 'r') as f:
        t0 = timeit.default_timer()
        RSA.RSA()
        t1 = timeit.default_timer()
        while(f.readline(117) != ''):
            t2 = timeit.default_timer()
            msg = f.readline(117)
            cipher = RSA.Encrypt(msg.encode()).encrypt()
            t3 = timeit.default_timer()
            e_time += t3-t2
            t4 = timeit.default_timer()
            decipher = RSA.Decrypt(cipher).decrypt()    
            t5 = timeit.default_timer()
            d_time += t5-t4

    print("RSA Key Generation Time: ", t1-t0)
    print("RSA Encryption Time: ", e_time)
    print("RSA Decryption Time: ", d_time)

def aes_test(file):
    t0 = timeit.default_timer()
    key = get_random_bytes(16)
    t1 = timeit.default_timer()

    t2 = timeit.default_timer()
    with open(file, 'r') as f:
        msg = f.read()
    cipher = AES.encrypt(key,msg.encode())
    with open('Encrypted.txt', 'w') as f:
        f.write(str(cipher[0]))
    t3 = timeit.default_timer()

    t4 = timeit.default_timer()
    decipher = AES.decrypt(cipher[0], key, cipher[2], cipher[1])
    with open('Decrypted.rtf', 'w') as f:
        f.write(decipher)
    t5 = timeit.default_timer()

    print("AES Key Generation Time: ", t1-t0)
    print("AES Encryption Time: ", t3-t2)
    print("AES Decryption Time: ", t5-t4)

if __name__ == '__main__':
    main()