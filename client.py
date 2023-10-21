import socket
import paramiko
import select
import threading
import sys

def usage():
    print("Usage: ch2_rforward.py localport ssh_address ssh_port remote_address remote_port")
    sys.exit(0)

#we initiate the remote socket and connect. we read from 2 data buffers: the remote socket
#and the channel associated with the forwarded connection and we relay the data to each.
#if there is no data, we close the socket and channel.
def handler(chan, remote_address, remote_port):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote_socket.connect((remote_address, remote_port))
    except:
        print(f"[!] Unable to establish tcp connection to {remote_address}:{remote_port}")
        sys.exit(1)

    print(f"[*] Established tcp connection to {remote_address}:{remote_port}")
    while True:
        r, w, x = select.select([remote_socket, chan], [], [])
        if remote_socket in r:
            data = remote_socket.recv(1024)
            if len(data) == 0:
                break
            print(f"[*] Sending {len(data)} bytes via SSH channel")
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            remote_socket.send(data)
            print(f"[*] Sending {len(data)} bytes via TCP socket")
    chan.close()
    remote_socket.close()
    print("[*] Tunnel connection is closed")

#request port forwarding from server and open a session ssh channel.
#forwarded connection will be picked up via the client transport's accept method
#within the infinite loop.
#thread will be spawned to handle the forwarded connection.
def reverse_port_forward(local_port, remote_address, remote_port, client_transport):
    print("[*] Starting reverse port forwarding")
    try:
        client_transport.request_port_forward("", local_port)
        client_transport.open_session()
    except paramiko.SSHException as err:
        print("[!] Unable to enable reverse port forwarding: ", str(err))
        sys.exit(1)
    print(f"[*] Started. Waiting for tcp connection on 127.0.0.1:{local_port} from SSH server")
    while True:
        try:
            chan = client_transport.accept(60)
            if not chan:
                continue
            thr = threading.Thread(target=handler, args=(chan, remote_address, remote_port))
            thr.start()
        except KeyboardInterrupt:
            client_transport.cancel_port_forward("", local_port)
            client_transport.close()
            sys.exit(0)

#check script args
if len(sys.argv[1:]) == 5:
    try:
        if int(sys.argv[1]) > 0 and int(sys.argv[1]) < 65536:
            local_port = int(sys.argv[1])
        else:
            raise Exception("Local port out of bounds")
        server_address = sys.argv[2]
        if int(sys.argv[3]) > 0 and int(sys.argv[3]) < 65536:
            server_port = int(sys.argv[3])
        else:
            raise Exception("Server port out of bounds")
        remote_address = sys.argv[4]
        if int(sys.argv[5]) > 0 and int(sys.argv[5]) < 65536:
            remote_port = int(sys.argv[5])
        else:
            raise Exception("Remote port out of bounds")
    except Exception as err:
        print("Invalid Arguments: " + str(err))
        usage()
else:
    usage()

#start the ssh client and ask for credentials
print("[*] SSH reverse port forwarding tool started")
server_username = input("Enter username: ")
server_password = input("Enter password: ")

client = paramiko.SSHClient()
#client.load_host_key('/path/to/file')
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(server_address, port=server_port, username=server_username, password=server_password)
except (paramiko.AuthenticationException, paramiko.SSHException) as err:
    print(str(err))
    sys.exit(1)
reverse_port_forward(local_port, remote_address, remote_port, client.get_transport())