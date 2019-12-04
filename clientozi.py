import select
import socket
import sys


if (len(sys.argv) < 4):
    print('Usage : python chat_client.py hostname port username')
    sys.exit()

host = sys.argv[1]
port = int(sys.argv[2])
name = sys.argv[3]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)

# connect to remote host
try:
    s.connect((host, port))
except:
    print('Unable to connect')
    sys.exit()

s.send(name.encode("utf-8"))
print('Connected to remote host. You can start sending messages')
sys.stdout.write('[Me] ')
sys.stdout.flush()

while 1:
    socket_list = [sys.stdin, s]

    # Get the list sockets which are readable
    ready_to_read, ready_to_write, in_error = select.select(socket_list, [], [])

    for sock in ready_to_read:
        if sock == s:
            # incoming message from remote server, s
            data = sock.recv(4096)
            if not data:
                print('\nDisconnected from chat server')
                sys.exit()
            else:
                # print data
                sys.stdout.write(data.decode("utf-8"))
                sys.stdout.write('[Me] ')
                sys.stdout.flush()

        else:
            # user entered a message
            msg = sys.stdin.readline()
            s.send(msg.encode("utf-8"))
            s.send(name.encode("utf-8"))
            sys.stdout.write('[Me] ')
            sys.stdout.flush()
