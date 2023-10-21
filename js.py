
import paramiko
import socket
import threading
import select
import sys

host_key = paramiko.RSAKey(filename='key.key')
server_address = sys.argv[1]
server_port = int(sys.argv[2])

#the server interface. Note that the socket is created here when the client requests
#forwarded connections
class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    def check_auth_password(self, username, password):
        if username == "user" and password == "password":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def check_port_forward_request(self, addr, port):
        self.listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen.bind(("127.0.0.1", int(port)))
        self.listen.listen(1)
        return self.listen.getsockname()[1]
    def cancel_port_forward_request(self, addr, port):
        self.listen.close()
        self.listen = None
    def check_channel_request(self, kind, chanid):
        if kind in ["forwarded-tcpip", "session"]:
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

#we create a server ssh transport with the client socket and start the ssh server.
#we create 2 channels: 1- session channel and 2- tunneled forward channel. The client requests
#the session channel. The server opens the forward channel after we accept the client's
#request to forward connections. We then read the data from the socket created locally for
#this tunneled forwarded connection and relay to the forward channel and vice versa
def client_handler(client_socket):
    session_transport = paramiko.Transport(client_socket)
    session_transport.add_server_key(host_key)
    server = Server()
    try:
        session_transport.start_server(server=server)
    except SSHException as err:
        print(f"[!] SSH Negotiation Failed")
        sys.exit(1)

    print(f"[*] SSH Negotiation Success")

    print("[*] Authenticating")
    session_chan = session_transport.accept(20)

    if session_chan == None or not session_chan.active:
        print("[!] Failure - SSH channel not active")
        session_transport.close()
    else:
        print("[*] Success - SSH channel active")
        while session_chan.active:
            try:
                try:
                    client_tunnel_socket, addr = server.listen.accept()
                except:
                    print("[*] Closing associated channels")
                    session_transport.close()
                    break
                print(f"[*] Incoming tunneled conenction from {addr[0]}:{addr[1]}")
                tunnel_chan = session_transport.open_forwarded_tcpip_channel(client_tunnel_socket.getsockname(), client_tunnel_socket.getpeername())
                while True:
                    r, w, x = select.select([client_tunnel_socket, tunnel_chan], [], [])
                    if client_tunnel_socket in r:
                        data = client_tunnel_socket.recv(1024)
                        if len(data) == 0:
                            break
                        print(f"[*] Sending {len(data)} bytes via SSH Channel")
                        tunnel_chan.send(data)
                    if tunnel_chan in r:
                        data = tunnel_chan.recv(1024)
                        if len(data) == 0:
                            break
                        print(f"[*] Sending {len(data)} bytes via TCP Channel")
                        client_tunnel_socket.send(data)
            except (paramiko.SSHException, Exception) as err:
                print("[*] ", str(err))
                try:
                    print("[*] Closing associated sockets and channels")
                    client_tunnel_socket.close()
                    session_transport.close()
                except:
                    pass

#bind the server to arguments parameters: address and port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    server_socket.bind((server_address, server_port))
except:
    print("[!] Bind Error")
    sys.exit(1)

print(f"[*] Bind Success {server_address}:{server_port}")
server_socket.listen(20)
#Keep listening to incoming connections and spawn a thread to handle it
while True:
    client_socket, addr = server_socket.accept()
    print(f"[*] Incoming TCP connection from {addr[0]}:{addr[1]}")
    client_thread = threading.Thread(target=client_handler, args=(client_socket,))
    client_thread.start()