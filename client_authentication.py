import socket
import rsa
import hashlib
import base64
import json

debug = False
app_server_private_key_pks = b'-----BEGIN RSA PRIVATE ' \
                         b'KEY-----\nMIICYQIBAAKBgQCyWp1SqRxJ2eMzBtUQnXhzwTBxGgxaNsGiC9IOLmdeZWWW6MXK' \
                         b'\ntg5TDtdexe8j4iDNVDVfzSYyly1Y9176U7z5oRIsudrXQqG2YleiX6AqOAD1p022\n4+v0t9ROeBhyzXaC' \
                         b'/ieJjLwt1NPVrliXzM+2LNmR1mb1oaF+N1whwrAX6wIDAQAB\nAoGAcNodSbxvhds0g4kDMCwzlyrad/Y' \
                         b'/cqXLB7nrA8Yg6f3GtiI7ZPSlQ7DUXcdo\ndZATqVhrHV81mDVIIE8FVAEeEZhQSkbM5edXysOs5/J2R7YksMD6O4G' \
                         b'+DuaYchLz\niRH5hKcKxwCw/M92qgdDIIdqThpNFZLOz7Jzl0EWpz0OKgECRQDzOZMgjncIWtiQ' \
                         b'\nkJwaquz3goeMKf3rWCY+f75oZi5lMsChZgrTsv8o+jdqQ5REVi8uCSpSv9+Ggfsn' \
                         b'\nJesCoZda3DCSqwI9ALu4x2vA1Z6AfjvXigV3kZYrWNV2KiRjbz0Gb9NCPhknPJvx' \
                         b'\nLIaaOORx328HMNo9T4EzWXE7IVNuQGyPwQJFAIOYCPQ6YEiS7kz5EJyVEfSwGKpL\nJeipHrf94YUWk8' \
                         b'+I8BPi48S6Obdv+X9y5Ms8XfZoWw++ZC+gL8R0jXw09XDhZR5V' \
                         b'\nAj0AlEbSDkTU90vbaf1IYiUd9BXtJz8c7n00QmmxLpemYUvizfJkDzYGNjvUFukB' \
                         b'\nJ4FCKXWb8pqYKkRt0tKBAkRvMx+DpdAHAyUWx24wi95Xlr6oMhUeZRtbqBqtOnGm' \
                         b'\npWD8VIXSGgEWaUroavRSNeo9ADFdKuD//uIM/q++4VzWP6UZ8w==\n-----END RSA PRIVATE KEY-----\n '


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

    # AES DECIPHER
    hashed = hashlib.sha256()
    hashed.update(bytes(password))
    pwhash = hashed.digest()
    daes = AES.new(pwhash, AES.MODE_ECB)
    decrypted_response = daes.decrypt(response)

    result = json.loads(decrypted_response)
    # Base64 decode the token from response
    token = base64.b64decode(result['token'])
    # If authentication failed
    if result['auth'] == 'fail':
        print("Authentication Failed, Error: ")
        print(token.decode())
    # If authentication successful
    else:
        print("Authentication Successful.")
        print("Token: ")
#        TODO SEND THIS TOKEN TO THE APP SERVER
        print(token)

#       TODO ON THE APP SERVER SIDE
        app_server_private_key = rsa.PrivateKey
        app_server_private_key = app_server_private_key.load_pkcs1(app_server_private_key_pks)
        decrypted = rsa.decrypt(token, app_server_private_key)
        print(decrypted.decode())

    client_socket.close()


if __name__ == '__main__':
    client_connection()
