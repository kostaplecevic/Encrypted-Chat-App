#!/usr/bin/env python3
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter as tk

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
            msg_list.insert(tk.getint(0), msg)
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

#GUI

top = tk.Tk()
sizex = 600
sizey = 300
posx  = 100
posy  = 100
top.wm_geometry("%dx%d+%d+%d" % (sizex, sizey, posx, posy))
top.title("Chatter")

messages_frame=tk.Frame(top,width=50,height=100,bd=1)
messages_frame.place(x=10,y=10)
messages_frame.pack()

msg_list = tk.Listbox(messages_frame, width=50, height=20, font=("Helvetica", 11))
msg_list.pack(side="left", fill="x")
msg_list.pack()

scrollbar = tk.Scrollbar(messages_frame, orient="vertical")
scrollbar.config(command=msg_list.yview)
scrollbar.pack(side="left", fill="y")
msg_list.config(yscrollcommand=scrollbar.set)

scrollbar2 = tk.Scrollbar(messages_frame, orient="horizontal")
scrollbar2.config(command=msg_list.xview)
scrollbar2.pack(side="bottom", fill="x")
msg_list.config(xscrollcommand=scrollbar2.set)

my_msg = tk.StringVar()
my_msg.set("")
canvas = tk.Canvas(messages_frame)
entry_field = tk.Entry(messages_frame, textvariable=my_msg)
entry_field.bind("<Return>", send)
canvas.create_window(250, 150, window=entry_field)
entry_field.focus_set()
entry_field.pack()

send_button = tk.Button(top, text="Send", command=send)
send_button.pack()

def on_closing(event=None):
    """Kada se klikne na x"""
    my_msg.set("{quit}")
    send()
top.protocol("WM_DELETE_WINDOW", on_closing)

#Addressing

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
tk.mainloop()  #Zapocinje GUI

