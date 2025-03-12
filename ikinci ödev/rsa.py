from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()  
    public_key = key.publickey().export_key().decode()
    return private_key, public_key


def encrypt_message(message, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode()

def decrypt_message(encrypted_message, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode()

if __name__ == "__main__":
    private_key, public_key = generate_keys()
    
    print("\n===== RSA Anahtarları =====")
    print("\n Public Key (Genel Anahtar):\n")
    print(public_key)
    print("\n Private Key (Özel Anahtar):\n")
    print(private_key)
    
    while True:
        print("\nRSA Şifreleme Programı")
        print("Şifreleme yapmak için 'E', çözme yapmak için 'D', çıkmak için 'Q' girin.")
        
        choice = input("Seçiminiz: ").strip().upper()

        if choice == "E":
            message = input("Şifrelenecek metni girin: ")
            encrypted_message = encrypt_message(message, public_key)
            print("\n Şifrelenmiş Mesaj:")
            print(encrypted_message)

        elif choice == "D":
            encrypted_message = input("Çözülecek şifrelenmiş metni girin: ")
            try:
                decrypted_message = decrypt_message(encrypted_message, private_key)
                print("\n Çözülmüş Mesaj:")
                print(decrypted_message)
            except Exception as e:
                print(" Şifre çözme başarısız! Hata:", str(e))

        elif choice == "Q":
            print("Programdan çıkılıyor...")
            break

        else:
            print("⚠️ Geçersiz giriş! Lütfen 'E', 'D' veya 'Q' girin.")