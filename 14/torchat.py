#!/usr/bin/env python3

# sudo apt install python3-socks
import argparse
import socks
import socket
import sys
import secrets  # https://docs.python.org/3/library/secrets.html

# do not use any other imports/libraries

# took 2.0 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TorChat client')
parser.add_argument('--myself', required=True, type=str, help='My TorChat ID')
parser.add_argument('--peer', required=True, type=str, help='Peer TorChat ID')
args = parser.parse_args()

myself_id = args.myself
peer_id = args.peer

if myself_id.endswith('.onion'):
    myself_id = myself_id[:-6]
if peer_id.endswith('.onion'):
    peer_id = peer_id[:-6]

peer_host = peer_id + '.onion'
peer_port = 11009

def send_torchat_cmd(sock, cmd):
    msg = (cmd + '\n').encode('utf-8')
    print("[+] Sending: %s" % cmd)
    try:
        sock.sendall(msg)
    except Exception:
        sys.exit(1)

# connect to peer through Tor SOCKS proxy
outgoing_socket = socks.socksocket()
outgoing_socket.set_proxy(socks.SOCKS5, '127.0.0.1', 9050)

try:
    print("[+] Connecting to peer %s" % peer_host)
    outgoing_socket.connect((peer_host, peer_port))
except Exception as e:
    print("[-] Could not connect to peer: %s" % e)
    sys.exit(1)

# generate 128-bit cookie (random decimal number)
cookie_myself = str(secrets.randbits(128))

# send ping over outgoing connection
send_torchat_cmd(outgoing_socket, "ping %s %s" % (myself_id, cookie_myself))

# listen for incoming connection on 127.0.0.1:8888
sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sserv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sserv.bind(('127.0.0.1', 8888))
sserv.listen(0)
print("[+] Listening...")
(incoming_socket, address) = sserv.accept()
print("[+] Client %s:%s" % (address[0], address[1]))

# function for reading one TorChat command from the socket
def read_torchat_cmd(incoming_socket):
    cmd_bytes = b""
    while True:
        try:
            ch = incoming_socket.recv(1)
        except Exception:
            sys.exit(1)
        if not ch:
            sys.exit(0)
        if ch == b'\n':
            break
        cmd_bytes += ch

    cmd = cmd_bytes.decode('utf-8', errors='replace')
    print("[+] Received: %s" % cmd)
    return cmd

incoming_authenticated = False
status_received = False
cookie_peer = ""
ping_received = False
pong_verified = False
pong_sent = False

# the main loop for processing the received commands
while True:
    cmdr = read_torchat_cmd(incoming_socket)

    cmd = cmdr.split(' ')

    if cmd[0] == 'ping':
        if len(cmd) >= 3:
            peer_from_ping = cmd[1]
            if peer_from_ping != peer_id:
                continue
            cookie_peer = cmd[2]
            ping_received = True
            if pong_verified and not pong_sent:
                send_torchat_cmd(outgoing_socket, "pong %s" % cookie_peer)
                pong_sent = True
                incoming_authenticated = True
                print("[+] Incoming connection authenticated!")

    elif cmd[0] == 'pong':
        if len(cmd) >= 2:
            if cmd[1] == cookie_myself:
                pong_verified = True
                if ping_received and not pong_sent:
                    send_torchat_cmd(outgoing_socket, "pong %s" % cookie_peer)
                    pong_sent = True
                    incoming_authenticated = True
                    print("[+] Incoming connection authenticated!")

    elif cmd[0] == 'status':
        if incoming_authenticated and not status_received:
            status_received = True
            send_torchat_cmd(outgoing_socket, "add_me")
            send_torchat_cmd(outgoing_socket, "status available")
            send_torchat_cmd(outgoing_socket, "profile_name Alice")

    elif cmd[0] == 'message':
        if incoming_authenticated:
            try:
                msg_out = input("[?] Enter message: ")
            except EOFError:
                msg_out = ""
            if msg_out != "":
                send_torchat_cmd(outgoing_socket, "message " + msg_out)

    else:
        pass

