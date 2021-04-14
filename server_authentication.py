import hashlib
import socket
import requests
import rsa
import base64
from Crypto.Cipher import AES

# App Server Public Key
app_server_public_key_pks = b'-----BEGIN RSA PUBLIC ' \
                            b'KEY-----\nMIGJAoGBALJanVKpHEnZ4zMG1RCdeHPBMHEaDFo2waIL0g4uZ15lZZboxcq2DlMO' \
                            b'\n117F7yPiIM1UNV/NJjKXLVj3XvpTvPmhEiy52tdCobZiV6JfoCo4APWnTbbj6/S3\n1E54GHLNdoL' \
                            b'+J4mMvC3U09WuWJfMz7Ys2ZHWZvWhoX43XCHCsBfrAgMBAAE=\n-----END RSA PUBLIC KEY-----\n '


def server_connection():
    # Server IP Address
    host = "127.0.0.1"
    port = 5000
    # Generate Public and Private Keys and load app server public key
    public_key, private_key = rsa.newkeys(1024)
    app_server_public_key = rsa.PublicKey
    app_server_public_key = app_server_public_key.load_pkcs1(app_server_public_key_pks)
    # Host the Server and Accept a Connection
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server Online")
    conn, address = server_socket.accept()
    print("\tConnection from: " + str(address))
    # Send the Public Key to the Client
    conn.send(public_key.save_pkcs1())
    # Receive the Encrypted Credentials and Decrypt them
    decrypted = rsa.decrypt(conn.recv(1024), private_key)
    client_credentials = decrypted.decode()
    username = client_credentials.split(' ')[0]
    password = client_credentials.split(' ')[1]
    # Send the credentials to the OAuth2 Server
    req = requests.post('http://52.14.213.84/oauth_provider/token.php', data={'grant_type': 'client_credentials'},
                        auth=(username, password))
    reply_complete = req.text
    print(reply_complete)
    reply = req.text.split("\"")
    # Read the response
    # Encrypt the entire access_token using the public key followed by base64 encryption
    response_end = "\"}"
    if reply[1] == "access_token":
        encrypted = rsa.encrypt(reply_complete.encode(), app_server_public_key)
        token = base64.b64encode(encrypted)
        response_first = "{\"auth\":\"success\",\"token\":\""
    else:
        response_first = "{\"auth\":\"fail\",\"token\":\""
        token = base64.b64encode(reply_complete.encode())
    response = response_first.encode() + token + response_end.encode()

    # AES ENCRYPT
    key = hashlib.sha256(password).hexdigest()
    cipher_text = base64.b64decode(response)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_response = cipher.encrypt(cipher_text)
    conn.send(encrypted_response)

    #conn.send(response)
    conn.close()  # close the connection


if __name__ == '__main__':
    server_connection()
