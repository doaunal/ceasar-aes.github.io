import socket
import random
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


PRIME = 23  
BASE = 5    

def generate_private_key():
    """Rastgele özel anahtar üret."""
    return random.randint(2, PRIME - 2)

def generate_public_key(private_key):
    """Ortak anahtar üret."""
    return (BASE ** private_key) % PRIME

def generate_shared_secret(private_key, public_key):
    """Ortak gizli anahtar üret."""
    return (public_key ** private_key) % PRIME

def encrypt_message(key, message):
    """AES ile mesaj şifrele."""
    key = key.to_bytes(16, byteorder='big')[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv=b'1234567890123456')
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ciphertext

def decrypt_message(key, ciphertext):
    """AES ile şifreli mesajı çöz."""
    key = key.to_bytes(16, byteorder='big')[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv=b'1234567890123456')
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def start_server():
    """Sunucu başlat ve istemciden mesaj al."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 5555))
    server.listen(1)
    print("Sunucu başlatıldı, istemci bekleniyor...")

    conn, addr = server.accept()
    print(f"Bağlantı kabul edildi: {addr}")

    
    server_private = generate_private_key()
    server_public = generate_public_key(server_private)

   
    print(f"[SUNUCU] Özel Anahtar: {server_private}")
    print(f"[SUNUCU] Ortak Anahtar: {server_public}")

    
    conn.send(str(server_public).encode())

    
    client_public = int(conn.recv(1024).decode())

    
    shared_secret = generate_shared_secret(server_private, client_public)
    print(f"[SUNUCU] Ortak Gizli Anahtar: {shared_secret}")

    def receive_messages():
        """İstemciden gelen mesajları al."""
        while True:
            try:
                ciphertext = conn.recv(1024)
                if not ciphertext:
                    break
                message = decrypt_message(shared_secret, ciphertext)
                print(f"[İstemci] {message}")
            except:
                break

    threading.Thread(target=receive_messages, daemon=True).start()

   
    while True:
        message = input("Sunucu: ")
        if message.lower() == "exit":
            break
        ciphertext = encrypt_message(shared_secret, message)
        conn.send(ciphertext)

    conn.close()
    server.close()

def start_client():
    """İstemci başlat ve sunucuya mesaj gönder."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5555))

   
    server_public = int(client.recv(1024).decode())

   
    client_private = generate_private_key()
    client_public = generate_public_key(client_private)

   
    print(f"[İSTEMCİ] Özel Anahtar: {client_private}")
    print(f"[İSTEMCİ] Ortak Anahtar: {client_public}")

   
    client.send(str(client_public).encode())

    
    shared_secret = generate_shared_secret(client_private, server_public)
    print(f"[İSTEMCİ] Ortak Gizli Anahtar: {shared_secret}")

    def receive_messages():
        """Sunucudan gelen mesajları al."""
        while True:
            try:
                ciphertext = client.recv(1024)
                if not ciphertext:
                    break
                message = decrypt_message(shared_secret, ciphertext)
                print(f"[Sunucu] {message}")
            except:
                break

    threading.Thread(target=receive_messages, daemon=True).start()

   
    while True:
        message = input("İstemci: ")
        if message.lower() == "exit":
            break
        ciphertext = encrypt_message(shared_secret, message)
        client.send(ciphertext)

    client.close()

if __name__ == "__main__":
    role = input("Sunucu (server) veya İstemci (client) olarak çalıştırmak ister misiniz? (server/client): ").strip().lower()
    
    if role == "server":
        start_server()
    elif role == "client":
        start_client()
    else:
        print("Geçersiz seçim! 'server' veya 'client' yazmalısınız.")