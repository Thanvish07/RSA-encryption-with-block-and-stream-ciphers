import tkinter as tk
import socket
import base64
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

class BobGUI:
    def __init__(self, master, sock):
        self.master = master
        self.master.title("Bob")
        self.master.geometry("800x600")

        # Frame for main content
        self.frame = tk.Frame(master, bg='#f0f0f0')
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Encryption Method Selection
        self.encryption_method = tk.StringVar(value="Block Cipher")

        encryption_frame = tk.LabelFrame(self.frame, text="Encryption Method", padx=10, pady=10, bg='#dcdcdc')
        encryption_frame.pack(pady=10, fill=tk.X)

        self.block_cipher_radio = tk.Radiobutton(encryption_frame, text="Block Cipher (AES)", variable=self.encryption_method, value="Block Cipher", bg='#dcdcdc')
        self.block_cipher_radio.pack(side=tk.LEFT, padx=5)
        self.stream_cipher_radio = tk.Radiobutton(encryption_frame, text="Stream Cipher (ChaCha20)", variable=self.encryption_method, value="Stream Cipher", bg='#dcdcdc')
        self.stream_cipher_radio.pack(side=tk.LEFT, padx=5)

        # Plaintext Section
        self.plaintext_frame = tk.LabelFrame(self.frame, text="Plaintext", padx=10, pady=10, bg='#e6e6e6')
        self.plaintext_frame.pack(fill=tk.BOTH, expand=True)

        self.plaintext_text = tk.Text(self.plaintext_frame, height=10, width=80, wrap=tk.NONE, bg='#ffffff')
        self.plaintext_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.plaintext_v_scroll = tk.Scrollbar(self.plaintext_frame, orient=tk.VERTICAL, command=self.plaintext_text.yview)
        self.plaintext_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.plaintext_text.config(yscrollcommand=self.plaintext_v_scroll.set)

        self.plaintext_h_scroll = tk.Scrollbar(self.plaintext_frame, orient=tk.HORIZONTAL, command=self.plaintext_text.xview)
        self.plaintext_h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.plaintext_text.config(xscrollcommand=self.plaintext_h_scroll.set)

        # Buttons for encrypting, refreshing, sending, and decrypting
        self.button_frame = tk.Frame(self.frame, bg='#f0f0f0')
        self.button_frame.pack(pady=10)

        self.encrypt_button = tk.Button(self.button_frame, text="Encrypt", command=self.encrypt, width=15, bg='#4CAF50', fg='white')
        self.encrypt_button.pack(side=tk.LEFT, padx=5)

        self.refresh_button = tk.Button(self.button_frame, text="Refresh", command=self.refresh, width=15, bg='#FFC107', fg='black')
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.send_button = tk.Button(self.button_frame, text="Send", command=self.send, width=15, bg='#2196F3', fg='white')
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.decrypt_button = tk.Button(self.button_frame, text="Decrypt", command=self.decrypt, width=15, bg='#FF5722', fg='white')
        self.decrypt_button.pack(side=tk.LEFT, padx=5)

        # Ciphertext Section
        self.ciphertext_frame = tk.LabelFrame(self.frame, text="Ciphertext", padx=10, pady=10, bg='#e6e6e6')
        self.ciphertext_frame.pack(fill=tk.BOTH, expand=True)

        self.ciphertext_text = tk.Text(self.ciphertext_frame, height=10, width=80, wrap=tk.NONE, bg='#ffffff')
        self.ciphertext_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.ciphertext_v_scroll = tk.Scrollbar(self.ciphertext_frame, orient=tk.VERTICAL, command=self.ciphertext_text.yview)
        self.ciphertext_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.ciphertext_text.config(yscrollcommand=self.ciphertext_v_scroll.set)

        self.ciphertext_h_scroll = tk.Scrollbar(self.ciphertext_frame, orient=tk.HORIZONTAL, command=self.ciphertext_text.xview)
        self.ciphertext_h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.ciphertext_text.config(xscrollcommand=self.ciphertext_h_scroll.set)

        # Received Ciphertext Section
        self.receive_frame = tk.LabelFrame(self.frame, text="Received Ciphertext", padx=10, pady=10, bg='#e6e6e6')
        self.receive_frame.pack(fill=tk.BOTH, expand=True)

        self.receive_text = tk.Text(self.receive_frame, height=10, width=80, wrap=tk.NONE, bg='#ffffff')
        self.receive_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.receive_v_scroll = tk.Scrollbar(self.receive_frame, orient=tk.VERTICAL, command=self.receive_text.yview)
        self.receive_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.receive_text.config(yscrollcommand=self.receive_v_scroll.set)

        self.receive_h_scroll = tk.Scrollbar(self.receive_frame, orient=tk.HORIZONTAL, command=self.receive_text.xview)
        self.receive_h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.receive_text.config(xscrollcommand=self.receive_h_scroll.set)

        # Decrypted Text Section
        self.decrypted_frame = tk.LabelFrame(self.frame, text="Decrypted Text", padx=10, pady=10, bg='#e6e6e6')
        self.decrypted_frame.pack(fill=tk.BOTH, expand=True)

        self.decrypted_text = tk.Text(self.decrypted_frame, height=10, width=80, wrap=tk.NONE, bg='#ffffff')
        self.decrypted_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.decrypted_v_scroll = tk.Scrollbar(self.decrypted_frame, orient=tk.VERTICAL, command=self.decrypted_text.yview)
        self.decrypted_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.decrypted_text.config(yscrollcommand=self.decrypted_v_scroll.set)

        self.decrypted_h_scroll = tk.Scrollbar(self.decrypted_frame, orient=tk.HORIZONTAL, command=self.decrypted_text.xview)
        self.decrypted_h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.decrypted_text.config(xscrollcommand=self.decrypted_h_scroll.set)

        # Setup for socket
        self.sock = sock

        # Load RSA keys (for encryption and decryption purposes)
        self.load_keys()

    def load_keys(self):
        """Load RSA keys from PEM files."""
        try:
            with open("bob_private_key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except Exception as e:
            print(f"Error loading Bob's private key: {e}")

        try:
            with open("alice_public_key.pem", "rb") as key_file:
                self.alice_public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        except Exception as e:
            print(f"Error loading Alice's public key: {e}")

    def encrypt(self):
        plaintext = self.plaintext_text.get("1.0", "end-1c")
        encryption_type = self.encryption_method.get()

        if encryption_type == "Block Cipher":
            key = os.urandom(32)  # AES-256 key
            iv = os.urandom(16)  # AES IV

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

            # Encode tag ('B' for Bob) + key, IV, and ciphertext for transmission
            tag = b'B'  # Tag to identify Bob's encryption
            key_iv_ciphertext = base64.b64encode(tag + key + iv + ciphertext).decode()
            self.ciphertext_text.delete("1.0", "end")
            self.ciphertext_text.insert("1.0", key_iv_ciphertext)

        elif encryption_type == "Stream Cipher":
            key = os.urandom(32)  # ChaCha20 key
            nonce = os.urandom(16)  # ChaCha20 nonce

            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

            # Encode tag ('B' for Bob) + key and nonce for transmission
            tag = b'B'  # Tag to identify Bob's encryption
            key_nonce_ciphertext = base64.b64encode(tag + key + nonce + ciphertext).decode()
            self.ciphertext_text.delete("1.0", "end")
            self.ciphertext_text.insert("1.0", key_nonce_ciphertext)

    def refresh(self):
        """Clears the input and output fields."""
        self.plaintext_text.delete("1.0", "end")
        self.ciphertext_text.delete("1.0", "end")
        self.receive_text.delete("1.0", "end")
        self.decrypted_text.delete("1.0", "end")

    def send(self):
        """Sends the ciphertext over the socket."""
        ciphertext = self.ciphertext_text.get("1.0", "end-1c")
        self.sock.sendall(ciphertext.encode())

    def receive(self):
        """Receives a message from Alice."""
        while True:
            try:
                received_ciphertext = self.sock.recv(4096).decode()
                self.receive_text.delete("1.0", "end")
                self.receive_text.insert("1.0", received_ciphertext)
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def decrypt(self):
        """Decrypts the received ciphertext."""
        received_ciphertext = self.receive_text.get("1.0", "end-1c")
        received_data = base64.b64decode(received_ciphertext.encode())

        encryption_type = self.encryption_method.get()
        plaintext = ""

        try:
            tag = received_data[:1]  # Read the tag (1 byte)
            if tag != b'A':  # Ensure it is a ciphertext from Alice
                raise ValueError("Decryption Error: Ciphertext not encrypted by Alice.")

            if encryption_type == "Block Cipher":
                key = received_data[1:33]  # AES-256 key
                iv = received_data[33:49]  # AES IV
                ciphertext = received_data[49:]

                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            elif encryption_type == "Stream Cipher":
                key = received_data[1:33]  # ChaCha20 key
                nonce = received_data[33:49]  # ChaCha20 nonce
                ciphertext = received_data[49:]

                cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Attempt to decode the plaintext to ensure it's valid UTF-8
            plaintext = plaintext.decode()

        except UnicodeDecodeError:
            plaintext = "Decryption Error: Invalid UTF-8 detected."

        except Exception as e:
            plaintext = "Decryption Error"

        self.decrypted_text.delete("1.0", "end")
        self.decrypted_text.insert("1.0", plaintext if plaintext.startswith("Decryption Error") else plaintext)


def start_server():
    host = 'localhost'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen()

        print("Waiting for connection from Alice...")
        conn, addr = sock.accept()
        print(f"Connected to {addr}")

        root = tk.Tk()
        bob_gui = BobGUI(root, conn)

        # Start a separate thread to listen for incoming messages
        threading.Thread(target=bob_gui.receive, daemon=True).start()

        root.mainloop()

if __name__ == "__main__":
    start_server()