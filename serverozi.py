
#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""

from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Crypto.Cipher import AES
import random

clients = {}
addresses = {}

HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

def getKey(key):
    key = key + " " * (16-len(key))
    return key.encode()

key = getKey("123")

def encodeData(data):
    return data.encode()

def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        msg = ("Greetings from the cave!"+
                          "Now type your name and press enter!").encode()
        bmsg = bytes(msg)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        client.send(nonce)

        ciphertext = cipher.encrypt(bmsg)
        client.send(ciphertext)
        print(ciphertext)
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()

def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""
    name = client.recv(BUFSIZ).decode()
    print(name)
    welcome = ('Welcome %s! If you ever want to quit, type {quit} to exit.' % name).encode()
    bwelcome = bytes(welcome)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    client.send(nonce)

    ciphertext = cipher.encrypt(bwelcome)
    client.send(ciphertext)
    msg = ("%s has joined the chat!" % name).encode()
    bmsg = bytes(msg)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    ciphertext = cipher.encrypt(bmsg)
    print(ciphertext)
    broadcast(nonce, ciphertext)
    clients[client] = name

    while True:
        msg = client.recv(BUFSIZ).decode()
        print(msg)
        if msg != bytes("{quit}", "utf8"):
            msg = msg.encode()
            bmsg = bytes(msg)
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext = cipher.encrypt(bmsg)
            print(ciphertext)
            broadcast(nonce, ciphertext)
        else:
            client_address = addresses[client]
            print("%s:%s has disconnected." % client_address)
            client.send(bytes("{quit}", "utf8"))
            client.close()
            del clients[client]
            broadcast(bytes("%s has left the chat." % name, "utf8"))
            break

def broadcast(nonce, msg):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for sock in clients:
        sock.send(nonce)
        sock.send(msg)


if __name__ == "__main__":
    SERVER.listen(5)  # Listens for 5 connections at max.
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()  # Starts the infinite loop.
    ACCEPT_THREAD.join()
    SERVER.close()

