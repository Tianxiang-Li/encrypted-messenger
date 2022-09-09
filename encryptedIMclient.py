import automator
import socket
import argparse
import select
import sys
import string
import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from encrypted_package_pb2 import EncryptedPackage, PlaintextAndMAC, IM
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-s', dest = 'servername', help = 'IP or hostname of the server', required = True)
    parser.add_argument('-n', dest = 'nickname', help = 'nickname chosen by user', required = True )
    parser.add_argument('-p', dest = 'portnumb', help = 'the port to connect', required = True)
    parser.add_argument('-c', dest = 'confidentialitykey', help = 'the cofidentiality key for AES-256-CBC encryption', required= True)
    parser.add_argument('-a', dest = 'authenticitykey', help = 'the authenticity key used to compute the SHA-256-based HMAC', required= True )
    # execute: python3 encryptedIMclient.py -p port -s servername -n nickname -c confidentialitykey -a authenticitykey

    args = parser.parse_args()
    nick = args.nickname
    server = args.servername
    pt = int(args.portnumb)
    c_key_hash = SHA256.new(str.encode(args.confidentialitykey))
    a_key_hash = SHA256.new(str.encode(args.authenticitykey))
    c_key = c_key_hash.digest()
    a_key = a_key_hash.digest()

    # create client socket and try to connect
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        clientsocket.connect( (server, pt))
    except ConnectionRefusedError:
        print("Cannot connect to the given server. Please check the servername and port.")
        exit(1)
    # create read_handler and use select to listen to both sys.stdin and from the server
    reader = [sys.stdin, clientsocket]

    while True:
        reader_list, _, _ = select.select(reader, [], [])
        failed_auth = False
        failed_conf = False

        if sys.stdin in reader_list:
            typed_message = input()
            # need to exit when user type "exit [enter]", case insensitive(to lower)
            
            is_exit = typed_message
            if is_exit.lower() == "exit":
                clientsocket.close()
                break
            #not exit, send message but first with Google Cloud Buffer
            # initialize IM
            im = IM()
            im.nickname = nick
            im.message = typed_message
            assert im.IsInitialized()
            serialized_im = im.SerializeToString()


            # Now MAC with anthenticity key
            plaintext = PlaintextAndMAC()
            padP = pad(serialized_im, AES.block_size)
            plaintext.paddedPlaintext = padP
            plain_hmac = HMAC.new(a_key,msg = padP, digestmod = SHA256)
            plaintext.mac = plain_hmac.digest()
            assert plaintext.IsInitialized()
            serialized_plaintext = plaintext.SerializeToString()

            # Now Encrypted message with confidential key
            encrypted_package = EncryptedPackage()
            iniv = get_random_bytes(AES.block_size)
            encrypted_package.iv = iniv
            cipher = AES.new(c_key, AES.MODE_CBC, iv = iniv)
            encrypted_package.encryptedMessage = cipher.encrypt(pad(serialized_plaintext, AES.block_size))
            assert encrypted_package.IsInitialized()
            serialized_encrypted_package = encrypted_package.SerializeToString()
            
            length_of_encrypted_package = len(serialized_encrypted_package)
            packed_length_of_encrypted_package = struct.pack('!L',length_of_encrypted_package)

            clientsocket.send(packed_length_of_encrypted_package)
            clientsocket.send(serialized_encrypted_package)

        if clientsocket in reader_list:
            # receive message from the server
            packed_length_of_encrypted_package = clientsocket.recv(4, socket.MSG_WAITALL)
            length_of_encrypted_package = struct.unpack('!L', packed_length_of_encrypted_package)[0] # unpack the length
            serialized_encrypted_package = clientsocket.recv(length_of_encrypted_package, socket.MSG_WAITALL) #receive the encrypted message

            # decrypt the encrypted package to get the serialized plaintext and mac
            encrypted_package = EncryptedPackage()
            encrypted_package.ParseFromString(serialized_encrypted_package)
            try: 
                cipher = AES.new(c_key, AES.MODE_CBC, iv = encrypted_package.iv)
                pad_serialzed_plaintext = cipher.decrypt(encrypted_package.encryptedMessage)
                serialized_plaintext = unpad(pad_serialzed_plaintext, AES.block_size)
            except :
                print('Wrong confidentiality key or the message is corrupted')
                failed_conf = True
            if not failed_conf:

                # verify the mac and the plaintext
                plaintext = PlaintextAndMAC()
                plaintext.ParseFromString(serialized_plaintext)
                plain_mac = HMAC.new(a_key, msg = plaintext.paddedPlaintext, digestmod = SHA256)
                try:
                    plain_mac.verify(plaintext.mac)
                except :
                    failed_auth = True
                    automator.hmac_verification_failed()
                if not failed_auth:
                    automator.hmac_verification_passed()
                    serialized_im = unpad(plaintext.paddedPlaintext, AES.block_size)

                    # deserialize the plaintext and get the nickname and message
                    im = IM()
                    im.ParseFromString(serialized_im)
                    automator.decrypted_IM(im)



if __name__ == '__main__':
    main()
