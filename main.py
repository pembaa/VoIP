import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import pyaudio
import time
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
import uuid

class SecureVoIPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure VoIP Application")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize audio constants
        self.CHUNK = 1024
        self.FORMAT = pyaudio.paInt16
        self.CHANNELS = 1
        self.RATE = 44100
        
        # Network settings
        self.server_socket = None
        self.client_socket = None
        self.is_connected = False
        self.is_server = False
        self.is_call_active = False
        
        # Cryptography components
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.session_key = None
        self.block_cipher_iv = None
        self.stream_cipher_nonce = None
        
        # Audio components
        self.audio = pyaudio.PyAudio()
        self.stream_in = None
        self.stream_out = None
        
        # Create UI
        self.create_ui()
        
        # Generate keypair on startup
        self.generate_keys()
        
    def create_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        conn_frame.pack(fill=tk.X, pady=5)
        
        # IP address entry
        ttk.Label(conn_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(conn_frame, textvariable=self.ip_var, width=15).grid(row=0, column=1, padx=5, pady=5)
        
        # Port entry
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.port_var = tk.StringVar(value="50000")
        ttk.Entry(conn_frame, textvariable=self.port_var, width=6).grid(row=0, column=3, padx=5, pady=5)
        
        # Connection buttons
        self.host_btn = ttk.Button(conn_frame, text="Host Call", command=self.start_server)
        self.host_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.join_btn = ttk.Button(conn_frame, text="Join Call", command=self.connect_to_server)
        self.join_btn.grid(row=0, column=5, padx=5, pady=5)
        
        self.end_btn = ttk.Button(conn_frame, text="End Call", command=self.end_call, state=tk.DISABLED)
        self.end_btn.grid(row=0, column=6, padx=5, pady=5)
        
        # Cryptography options frame
        crypto_frame = ttk.LabelFrame(main_frame, text="Cryptography Settings", padding="10")
        crypto_frame.pack(fill=tk.X, pady=5)
        
        # Block cipher selection
        ttk.Label(crypto_frame, text="Block Cipher:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.block_cipher_var = tk.StringVar(value="AES-256")
        block_combo = ttk.Combobox(crypto_frame, textvariable=self.block_cipher_var, width=10, state="readonly")
        block_combo['values'] = ('AES-128', 'AES-192', 'AES-256')
        block_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Stream cipher selection
        ttk.Label(crypto_frame, text="Stream Cipher:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.stream_cipher_var = tk.StringVar(value="ChaCha20")
        stream_combo = ttk.Combobox(crypto_frame, textvariable=self.stream_cipher_var, width=10, state="readonly")
        stream_combo['values'] = ('ChaCha20', 'AES-CTR')
        stream_combo.grid(row=0, column=3, padx=5, pady=5)
        
        # Key exchange info
        ttk.Label(crypto_frame, text="PKI Status:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.pki_status_var = tk.StringVar(value="Keys Generated")
        ttk.Label(crypto_frame, textvariable=self.pki_status_var).grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Call status and log frame
        status_frame = ttk.LabelFrame(main_frame, text="Call Status", padding="10")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Status indicator
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.status_var = tk.StringVar(value="Disconnected")
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Log area
        self.log_area = scrolledtext.ScrolledText(status_frame, height=15, wrap=tk.WORD)
        self.log_area.grid(row=1, column=0, columnspan=4, sticky=tk.NSEW, padx=5, pady=5)
        status_frame.grid_rowconfigure(1, weight=1)
        status_frame.grid_columnconfigure(3, weight=1)
        
        # Add log message
        self.add_log("Application started. Generated RSA keypair.")
    
    def generate_keys(self):
        try:
            # Generate RSA key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # Serialize public key for sharing
            self.public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.add_log("RSA keypair generated successfully.")
        except Exception as e:
            self.add_log(f"Error generating keys: {str(e)}")
    
    def start_server(self):
        if self.is_connected:
            return
        
        try:
            port = int(self.port_var.get())
            ip = self.ip_var.get()
            
            # Start server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((ip, port))
            self.server_socket.listen(1)
            
            self.is_server = True
            self.status_var.set("Waiting for connection...")
            self.add_log(f"Server started on {ip}:{port}. Waiting for incoming connection...")
            
            # Update UI buttons
            self.host_btn.config(state=tk.DISABLED)
            self.join_btn.config(state=tk.DISABLED)
            self.end_btn.config(state=tk.NORMAL)
            
            # Start accepting thread
            threading.Thread(target=self.accept_connection, daemon=True).start()
            
        except Exception as e:
            self.add_log(f"Error starting server: {str(e)}")
    
    def accept_connection(self):
        try:
            self.client_socket, addr = self.server_socket.accept()
            self.is_connected = True
            self.status_var.set(f"Connected to {addr[0]}:{addr[1]}")
            self.add_log(f"Client connected from {addr[0]}:{addr[1]}")
            
            # Start key exchange
            self.initiate_key_exchange()
            
        except Exception as e:
            if not self.server_socket._closed:
                self.add_log(f"Error accepting connection: {str(e)}")
    
    def connect_to_server(self):
        if self.is_connected:
            return
        
        try:
            port = int(self.port_var.get())
            ip = self.ip_var.get()
            
            # Create client socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, port))
            
            self.is_connected = True
            self.is_server = False
            self.status_var.set(f"Connected to {ip}:{port}")
            self.add_log(f"Connected to server at {ip}:{port}")
            
            # Update UI buttons
            self.host_btn.config(state=tk.DISABLED)
            self.join_btn.config(state=tk.DISABLED)
            self.end_btn.config(state=tk.NORMAL)
            
            # Begin key exchange
            self.initiate_key_exchange()
            
        except Exception as e:
            self.add_log(f"Error connecting to server: {str(e)}")
    
    def initiate_key_exchange(self):
        try:
            # Send public key to peer
            public_key_data = {
                "type": "public_key",
                "key": self.public_key_pem.decode('utf-8')
            }
            self.send_json(public_key_data)
            self.add_log("Sent public key to peer.")
            
            # Start thread to receive messages
            threading.Thread(target=self.receive_data, daemon=True).start()
            
        except Exception as e:
            self.add_log(f"Error during key exchange: {str(e)}")
    
    def receive_data(self):
        buffer = b""
        
        try:
            while self.is_connected:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Try to process complete messages from buffer
                while b'\n' in buffer:
                    msg_data, buffer = buffer.split(b'\n', 1)
                    self.process_received_data(msg_data)
                    
        except Exception as e:
            if self.is_connected:  # Only log if not deliberately disconnected
                self.add_log(f"Connection error: {str(e)}")
                self.cleanup_connection()
    
    def process_received_data(self, data):
        try:
            # Try to decode as JSON first (for control messages)
            try:
                json_data = json.loads(data.decode('utf-8'))
                
                # Handle different message types
                if json_data.get("type") == "public_key":
                    # Received peer's public key
                    peer_key_pem = json_data.get("key").encode('utf-8')
                    self.peer_public_key = serialization.load_pem_public_key(
                        peer_key_pem,
                        backend=default_backend()
                    )
                    self.add_log("Received peer's public key.")
                    self.pki_status_var.set("Key Exchange Complete")
                    
                    # If server, generate and send session keys
                    if self.is_server:
                        self.generate_session_keys()
                
                elif json_data.get("type") == "session_keys":
                    # Received encrypted session keys
                    encrypted_session_key = base64.b64decode(json_data.get("session_key"))
                    encrypted_block_iv = base64.b64decode(json_data.get("block_iv"))
                    encrypted_stream_nonce = base64.b64decode(json_data.get("stream_nonce"))
                    
                    # Decrypt session keys with private key
                    self.session_key = self.private_key.decrypt(
                        encrypted_session_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    self.block_cipher_iv = self.private_key.decrypt(
                        encrypted_block_iv,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    self.stream_cipher_nonce = self.private_key.decrypt(
                        encrypted_stream_nonce,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    self.add_log("Session keys received and decrypted.")
                    self.start_call()
                
                elif json_data.get("type") == "text_message":
                    # Received encrypted text message
                    encrypted_text = base64.b64decode(json_data.get("data"))
                    # Decrypt using block cipher
                    decrypted_text = self.decrypt_block(encrypted_text)
                    
                    # Display in chat
                    self.add_log(f"Peer: {decrypted_text.decode('utf-8')}")
                
                elif json_data.get("type") == "call_ended":
                    self.add_log("Peer ended the call.")
                    self.cleanup_connection()
                
            except json.JSONDecodeError:
                # Not JSON, must be encrypted audio data
                if self.is_call_active and self.session_key:
                    # Base64 decode first
                    binary_data = base64.b64decode(data)
                    # Decrypt using stream cipher
                    audio_data = self.decrypt_stream(binary_data)
                    
                    # Play the audio if stream is active
                    if self.stream_out:
                        self.stream_out.write(audio_data)
        
        except Exception as e:
            self.add_log(f"Error processing received data: {str(e)}")
    
    def generate_session_keys(self):
        try:
            # Generate random session key (256 bits)
            self.session_key = os.urandom(32)
            # Generate IV for block cipher (16 bytes for AES)
            self.block_cipher_iv = os.urandom(16)
            # Generate nonce for stream cipher (12 bytes for ChaCha20)
            self.stream_cipher_nonce = os.urandom(12)
            
            # Encrypt session key with peer's public key
            encrypted_session_key = self.peer_public_key.encrypt(
                self.session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt IV with peer's public key
            encrypted_block_iv = self.peer_public_key.encrypt(
                self.block_cipher_iv,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt nonce with peer's public key
            encrypted_stream_nonce = self.peer_public_key.encrypt(
                self.stream_cipher_nonce,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Send encrypted keys to peer
            keys_data = {
                "type": "session_keys",
                "session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
                "block_iv": base64.b64encode(encrypted_block_iv).decode('utf-8'),
                "stream_nonce": base64.b64encode(encrypted_stream_nonce).decode('utf-8')
            }
            
            self.send_json(keys_data)
            self.add_log("Generated and sent session keys.")
            
            # Start the call
            self.start_call()
            
        except Exception as e:
            self.add_log(f"Error generating session keys: {str(e)}")
    
    def start_call(self):
        if not self.is_call_active and self.session_key:
            try:
                # Set up audio streams
                self.stream_in = self.audio.open(
                    format=self.FORMAT,
                    channels=self.CHANNELS,
                    rate=self.RATE,
                    input=True,
                    frames_per_buffer=self.CHUNK
                )
                
                self.stream_out = self.audio.open(
                    format=self.FORMAT,
                    channels=self.CHANNELS,
                    rate=self.RATE,
                    output=True,
                    frames_per_buffer=self.CHUNK
                )
                
                self.is_call_active = True
                self.status_var.set("Call Active")
                self.add_log("Call started. Secure communication established.")
                
                # Start audio transmission thread
                threading.Thread(target=self.transmit_audio, daemon=True).start()
                
            except Exception as e:
                self.add_log(f"Error starting audio streams: {str(e)}")
    
    def transmit_audio(self):
        try:
            while self.is_call_active and self.is_connected:
                # Read audio from microphone
                audio_data = self.stream_in.read(self.CHUNK, exception_on_overflow=False)
                
                # Encrypt audio data with stream cipher
                encrypted_data = self.encrypt_stream(audio_data)
                
                # Base64 encode for transmission
                encoded_data = base64.b64encode(encrypted_data)
                
                # Send to peer
                if self.client_socket:
                    try:
                        self.client_socket.sendall(encoded_data + b'\n')
                    except:
                        break
                
                # Small delay to prevent CPU overuse
                time.sleep(0.01)
                
        except Exception as e:
            if self.is_call_active:  # Only log if not deliberately stopped
                self.add_log(f"Error in audio transmission: {str(e)}")
    
    def encrypt_stream(self, data):
        if self.stream_cipher_var.get() == "ChaCha20":
            cipher = ChaCha20Poly1305(self.session_key)
            # Create unique nonce for each packet
            unique_nonce = bytearray(self.stream_cipher_nonce)
            # Use a counter to ensure nonce uniqueness
            counter = int.from_bytes(unique_nonce[-4:], byteorder='little')
            counter = (counter + 1) % 0xFFFFFFFF
            unique_nonce[-4:] = counter.to_bytes(4, byteorder='little')
            
            # Encrypt data
            encrypted = cipher.encrypt(bytes(unique_nonce), data, None)
            
            # Return nonce + encrypted data
            return bytes(unique_nonce) + encrypted
        
        elif self.stream_cipher_var.get() == "AES-CTR":
            # For AES-CTR, we need a 16-byte nonce
            cipher = Cipher(
                algorithms.AES(self.session_key),
                modes.CTR(self.stream_cipher_nonce + (b'\x00' * 4)),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            return self.stream_cipher_nonce + encryptor.update(data) + encryptor.finalize()
    
    def decrypt_stream(self, data):
        try:
            if self.stream_cipher_var.get() == "ChaCha20":
                # Extract nonce from data
                nonce = data[:12]
                ciphertext = data[12:]
                
                cipher = ChaCha20Poly1305(self.session_key)
                return cipher.decrypt(nonce, ciphertext, None)
            
            elif self.stream_cipher_var.get() == "AES-CTR":
                # Extract nonce
                nonce = data[:12]
                ciphertext = data[12:]
                
                cipher = Cipher(
                    algorithms.AES(self.session_key),
                    modes.CTR(nonce + (b'\x00' * 4)),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                return decryptor.update(ciphertext) + decryptor.finalize()
        
        except Exception as e:
            self.add_log(f"Decryption error: {str(e)}")
            return b'\x00' * self.CHUNK  # Return silence on error
    
    def encrypt_block(self, data):
        # Get key size from selection
        if self.block_cipher_var.get() == "AES-128":
            key_size = 16  # 128 bits
        elif self.block_cipher_var.get() == "AES-192":
            key_size = 24  # 192 bits
        else:  # AES-256
            key_size = 32  # 256 bits
        
        # Derive key of correct size from session key
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=self.block_cipher_iv[:8],  # Use part of IV as salt
            iterations=1,  # Just one iteration for speed
            backend=default_backend()
        ).derive(self.session_key)
        
        # Pad data to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt with AES
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(self.block_cipher_iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def decrypt_block(self, data):
        # Get key size from selection
        if self.block_cipher_var.get() == "AES-128":
            key_size = 16  # 128 bits
        elif self.block_cipher_var.get() == "AES-192":
            key_size = 24  # 192 bits
        else:  # AES-256
            key_size = 32  # 256 bits
        
        # Derive key of correct size from session key
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=self.block_cipher_iv[:8],  # Use part of IV as salt
            iterations=1,  # Just one iteration for speed
            backend=default_backend()
        ).derive(self.session_key)
        
        # Decrypt with AES
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.CBC(self.block_cipher_iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(data) + decryptor.finalize()
        
        # Unpad data
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    
    def send_json(self, data):
        if self.client_socket:
            try:
                json_data = json.dumps(data).encode('utf-8') + b'\n'
                self.client_socket.sendall(json_data)
            except Exception as e:
                self.add_log(f"Error sending data: {str(e)}")
    
    def add_log(self, message):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_area.see(tk.END)
        self.log_area.configure(state=tk.DISABLED)
    
    def end_call(self):
        if self.is_connected:
            try:
                # Send call ended message
                self.send_json({"type": "call_ended"})
            except:
                pass
            
            self.cleanup_connection()
    
    def cleanup_connection(self):
        # Stop audio streams
        if self.stream_in:
            self.stream_in.stop_stream()
            self.stream_in.close()
            self.stream_in = None
        
        if self.stream_out:
            self.stream_out.stop_stream()
            self.stream_out.close()
            self.stream_out = None
        
        # Close socket connections
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        # Reset state
        self.is_connected = False
        self.is_call_active = False
        self.is_server = False
        self.peer_public_key = None
        
        # Update UI
        self.status_var.set("Disconnected")
        self.pki_status_var.set("Keys Generated")
        self.host_btn.config(state=tk.NORMAL)
        self.join_btn.config(state=tk.NORMAL)
        self.end_btn.config(state=tk.DISABLED)
        
        self.add_log("Call ended. Connection closed.")
    
    def on_closing(self):
        self.end_call()
        
        if self.audio:
            self.audio.terminate()
        
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureVoIPApp(root)
    root.mainloop()