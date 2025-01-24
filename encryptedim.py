## Assignment: Homework 1, Part 2
## Author: Tygan Chin
## Date: 2/22/2024
## Purpose: An encrypted IM messenger between a host and a client. The user 
##          can either open the server as the host or connect with the host 
##          and send messages back and forth with each other.

# imported libraries
import sys, select, socket 
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

# error messages
INPUT_ERROR = "usage: unencryptedim.py [--s|--c hostname] --confkey 'key 1' --authkey 'key 2'"
HMAC_ERROR = "ERROR: HMAC verification failed"

# ensure correct argument(s) was passed in and assign keys
keyhash1 = keyhash2 = None
numArguments = len(sys.argv)
if numArguments == 6:
    if sys.argv[1] != "--s" or sys.argv[2] != "--confkey" or sys.argv[4] != "--authkey": 
        print(INPUT_ERROR)
        sys.exit(1)
    keyhash1 = SHA256.new(sys.argv[3].encode())
    keyhash2 = SHA256.new(sys.argv[5].encode())
elif numArguments == 7:
    if sys.argv[1] != "--c" or sys.argv[3] != "--confkey" or sys.argv[5] != "--authkey": 
        print(INPUT_ERROR)
        sys.exit(1)
    keyhash1 = SHA256.new(sys.argv[4].encode())
    keyhash2 = SHA256.new(sys.argv[6].encode())
else:
    print(INPUT_ERROR)
    sys.exit(1)
confkey = keyhash1.digest()
authkey = keyhash2.digest()

# init socket and have it forgo its wait state when its closed
net_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
net_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# wait to connect with another socket or join a host
inputs = [sys.stdin]
if sys.argv[1] == "--s":
    net_socket.bind(('localhost', 9999))
    net_socket.listen(1)
    connection, address = net_socket.accept()
    inputs.append(connection)
else:
    net_socket.connect((sys.argv[2], 9999))
    inputs.append(net_socket)

# encrypts the given message and returns encryption
def encrypt(m):

    # init AES CBC mode encrypter with iv
    iv = get_random_bytes(16)
    cipher = AES.new(confkey, AES.MODE_CBC, iv)

    # encrypt length of message and mac the iv + len
    length = cipher.encrypt(len(m).to_bytes(16, byteorder='big'))
    hmac1 = HMAC.new(authkey, digestmod=SHA256)
    hmac1.update(iv + length)
    mac1 = hmac1.digest()
   
    # encrypt and mac the message 
    ciphertext = cipher.encrypt(m + bytes(16 - (len(m) % 16)))
    hmac2 = HMAC.new(authkey, digestmod=SHA256)
    hmac2.update(ciphertext)
    mac2 = hmac2.digest()
    
    # return concatenation of the macs and encryptions
    return iv + length + mac1 + ciphertext + mac2

# decrypts the given message and returns the decryption
def decrypt(m):

    # init decrypter
    decipher = AES.new(confkey, AES.MODE_CBC, m[:16])

    # decrypt length
    hmac1 = HMAC.new(authkey, digestmod=SHA256)
    hmac1.update(m[:32])
    if hmac1.digest() != m[32:64]:
        print(HMAC_ERROR)
        raise KeyboardInterrupt
    len = int.from_bytes(decipher.decrypt(m[16:32]), byteorder='big')
    
    # decrypt message
    lastByte = 64 + len + (16 - (len % 16))
    hmac2 = HMAC.new(authkey, digestmod=SHA256)
    hmac2.update(m[64:lastByte])
    if hmac2.digest() != m[lastByte:lastByte + 32]:
        print(HMAC_ERROR)
        raise KeyboardInterrupt
    decryption = decipher.decrypt(m[64:lastByte])

    # return decryption minus the padding
    return decryption[:len]

# send/display messages until eof/ctr-c is inputted or received
try:
    while True:
        (ready_read,_,_) = select.select(inputs, [], [])
        for sock in ready_read:
            if sock is sys.stdin:
                message = sys.stdin.readline()
                if not message:
                    raise KeyboardInterrupt
                inputs[1].send(encrypt(message.encode()))
            else:
                data = sock.recv(2048)
                if not data:
                    raise KeyboardInterrupt
                sys.stdout.write((decrypt(data)).decode())
                sys.stdout.flush()
except KeyboardInterrupt:
    inputs[1].send(b"")
    net_socket.close()