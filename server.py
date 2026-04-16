import socket
import threading
from main import generate_keys, encode_message, decode_message, symmetric_encrypt, symmetric_decrypt

SEPARATOR = "||"


class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.client_secrets = {}

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...
        self.e, self.d, self.n = generate_keys()
        self.secret = "AndriiMuzychyk123"

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # receive client's public key
            client_pub = c.recv(1024).decode()
            client_e, client_n = client_pub.split(SEPARATOR)
            client_e, client_n = int(client_e), int(client_n)

            # send public key to the client
            pub_key_msg = f"{self.e}{SEPARATOR}{self.n}"
            c.send(pub_key_msg.encode())

            import time
            time.sleep(0.1)

           # encrypt the secret with the clients public key
            secret_hash, secret_cipher = encode_message(self.secret, client_e, client_n)
            secret_msg = f"{secret_hash}{SEPARATOR}{secret_cipher}"


            # send the encrypted secret to a client
            c.send(secret_msg.encode())
            self.client_secrets[c] = self.secret


            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients:

            # encrypt the message

            encrypted = symmetric_encrypt(msg, self.client_secrets[client])
            client.send(encrypted.encode())

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(1024)
            for client in self.clients:
                if client != c:
                    client.send(msg)


if __name__ == "__main__":
    s = Server(9001)
    s.start()
