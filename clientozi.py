#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
import time
import os
from Crypto.Cipher import AES

def getKey(key):
    key = key + " " * (16-len(key))
    return key.encode()
key = getKey("123")

def decodeData(data):
    return data.decode()

def receive():
    while True:
        try:
            nonce = client_socket.recv(BUFSIZ)
            ciphertext = client_socket.recv(BUFSIZ)
            print(ciphertext)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decoded = cipher.decrypt(ciphertext)
            print(decoded)
            msg = decoded.decode()
            print(msg)
            msg_list.insert(tkinter.END, msg)
        except OSError:  # Ako klijent nasilno izadje
            break

def send(event=None):
    msg = my_msg.get()  #Uzima poruku iz textbox-a
    my_msg.set("")      #Briše sve iz textbox-a
    client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        time.sleep(1)
        client_socket.close()
        time.sleep(1)
        top.quit()
        #top.destroy()
        os._exit(0)

#def on_closing(event=None):
    #my_msg.set("{quit}")
    #send()

top = tkinter.Tk()
top.title("Leo Chat")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()
my_msg.set(" ")
scrollbar = tkinter.Scrollbar(messages_frame)

msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

#top.protocol("WM_DELETE_WINDOW", on_closing)

HOST = input('Enter host: ')
PORT = input('Enter port: ')
if not PORT:
    PORT = 33000  # Default value.
else:
    PORT = int(PORT)

BUFSIZ = 1024
ADDR = (HOST, PORT)
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  #Zapocinje GUI

