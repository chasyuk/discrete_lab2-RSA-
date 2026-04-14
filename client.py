import socket
import threading
from main import generate_keys, decode_message, symmetric_encrypt, symmetric_decrypt

SEPARATOR = "||"


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())

        # create key pairs

        self.e, self.d, self.n = generate_keys()
        pub_key_msg = f"{self.e}{SEPARATOR}{self.n}"
        self.s.send(pub_key_msg.encode())

        # exchange public keys

        server_pub = self.s.recv(1024).decode()
        server_e, server_n = server_pub.split(SEPARATOR)
        server_e, server_n = int(server_e), int(server_n)
        print("[client] Received server's public key")

        # receive the encrypted secret key

        secret_msg = self.s.recv(1024).decode()
        secret_hash, secret_cipher = secret_msg.split(SEPARATOR)
        secret_cipher = int(secret_cipher)
        self.secret = decode_message((secret_hash, secret_cipher), self.d, self.n)
        print("[client] Received and decrypted shared secret")

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        while True:
            message = self.s.recv(1024).decode()

            # decrypt message with the secret key

            message = symmetric_decrypt(message, self.secret)

            print(message)

    def write_handler(self):
        while True:
            message = input()

            # encrypt message with the secret key

            message = symmetric_encrypt(message, self.secret)

            self.s.send(message.encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
