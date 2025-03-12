from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hmac
import hashlib


def generate_hmac(key, data):
    """HMAC-SHA256 üretme fonksiyonu."""
    return hmac.new(key.encode('utf-8'), data, hashlib.sha256).digest()


def encrypt(plain_text, key):
    key = hashlib.sha256(key.encode('utf-8')).digest()[:32]  
    cipher = AES.new(key, AES.MODE_CBC)
    
    padded_data = pad(plain_text.encode('utf-8'), AES.block_size)
    ct_bytes = cipher.encrypt(padded_data)

    hmac_value = generate_hmac(base64.b64encode(key).decode(), ct_bytes)  
    
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext = base64.b64encode(ct_bytes).decode('utf-8')
    hmac_encoded = base64.b64encode(hmac_value).decode('utf-8')

    return f"{iv}:{ciphertext}:{hmac_encoded}"


def decrypt(encrypted_text, key):
    try:
        iv, ciphertext, hmac_received = encrypted_text.split(":")
    except ValueError:
        raise ValueError("Şifreli metin yanlış formatta!")

    iv = base64.b64decode(iv)
    ciphertext = base64.b64decode(ciphertext)
    hmac_received = base64.b64decode(hmac_received)

    key = hashlib.sha256(key.encode('utf-8')).digest()[:32]  
    
    hmac_calculated = generate_hmac(base64.b64encode(key).decode(), ciphertext)
    if not hmac.compare_digest(hmac_received, hmac_calculated):
        raise ValueError("HMAC doğrulaması başarısız!")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return decrypted_data.decode('utf-8')


def encrypt_input():
    plain_text = input("Şifrelemek istediğiniz metni girin: ")
    key = input("Şifrelemek için bir anahtar girin (32 karaktere kadar): ")
    encrypted_text = encrypt(plain_text, key)
    print("\nŞifreli Metin:")
    print(encrypted_text)


def decrypt_input():
    encrypted_text = input("Çözmek istediğiniz şifreli metni girin (IV:ŞifreliMetin:HMAC formatında): ")
    key = input("Şifre çözme için bir anahtar girin (32 karaktere kadar): ")
    try:
        decrypted_text = decrypt(encrypted_text, key)
        print("\nÇözülmüş Metin:", decrypted_text)
    except Exception as e:
        print(f"Bir hata oluştu: {e}")


def main():
    while True:
        print("\nAES + HMAC Şifreleme ve Çözme")
        choice = input("Şifreleme yapmak için 'E', çözme yapmak için 'D', çıkmak için 'Q' girin: ").upper()

        if choice == 'E':
            encrypt_input()
        elif choice == 'D':
            decrypt_input()
        elif choice == 'Q':
            print("Çıkılıyor...")
            break
        else:
            print("Geçersiz seçim! Lütfen 'E', 'D' veya 'Q' girin.")

if __name__ == "__main__":
    main()