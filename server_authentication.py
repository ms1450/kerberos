import hashlib
import socket
import requests
import rsa
import pycrypto

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
    reply = req.text.split("\"")
    # Read the response
    if reply[1] == "access_token":
        encrypted = rsa.encrypt(reply_complete.encode(), app_server_public_key)
        response_first = b"{\"auth\":\"success\",\"token\":\""
        response_second = b"\"}"
    else:
        encrypted = b""
        response_first = b"{\"auth\":\"fail\",\"token\":\""
        response_second = b"\"}"
    response = response_first + encrypted + response_second
    # Hashes the password of the client
    hashed = hashlib.sha256()
    hashed.update(bytes(password))
    pwhash = hashed.digest()
    # Encrypts the response using SHA256 hash
    # TODO AES ENCRYPTION
    obj = AES.new(pwhash, AES.MODE_ECB)
    encrypted_response = obj.encrypt(response)
    # Sends the encrypted data to the client
    conn.send(encrypted_response)
    conn.close()  # close the connection


if __name__ == '__main__':
    server_connection()
