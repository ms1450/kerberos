import socket
import rsa
import hmac
import hashlib
import base64

debug = False


def client_connection():
    # Server IP Address
    host = "127.0.0.1"
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))
    # Receive Public key from the server
    data = client_socket.recv(1024)
    # Server Public Key
    server_public_key = rsa.PublicKey
    server_public_key = server_public_key.load_pkcs1(data)
    if debug:
        print(server_public_key)
    # Take in User Credentials
    # No Spaces allowed in the Username
    username = input("Enter Your Username: ")
    password = input("Enter Your Password: ")
    credentials = username + ' ' + password
    # Encode in the Servers Public Key
    encrypted = rsa.encrypt(credentials.encode(), server_public_key)
    # Send encoded credentials
    client_socket.send(encrypted)
    response = client_socket.recv(1024)
#TODO Receive the SHA256 Encrypted Response, Decrypt it and send to app server
    client_socket.close()


if __name__ == '__main__':
    client_connection()
