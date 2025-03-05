from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


def encrypt(plain_text, key):
    key = key.ljust(32)[:32]  
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)  
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))  
    iv = base64.b64encode(cipher.iv).decode('utf-8')  
    ciphertext = base64.b64encode(ct_bytes).decode('utf-8')  
    return iv, ciphertext 


def decrypt(encrypted_text, key):
    try:
        iv, ciphertext = encrypted_text.split(":")  
    except ValueError:
        raise ValueError("Şifreli metin yanlış formatta! Lütfen IV ve şifreyi ':' ile ayırarak girin.")
    
    iv = base64.b64decode(iv) 
    ciphertext = ciphertext + "=" * (4 - len(ciphertext) % 4)  
    ciphertext = base64.b64decode(ciphertext) 

    key = key.ljust(32)[:32]  
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)  
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)  
    return decrypted_data.decode('utf-8')  


def encrypt_input():
    plain_text = input("Şifrelemek istediğiniz metni girin: ")
    key = input("Şifrelemek için bir anahtar girin (32 karaktere kadar): ")
    iv, encrypted_text = encrypt(plain_text, key)
    print("\n Şifreli Metin:")
    print(f"IV: {iv}")
    print(f"Şifreli Metin: {encrypted_text}")


def decrypt_input():
    encrypted_text = input("Çözmek istediğiniz şifreli metni girin (IV ve Şifreyi ':' ile ayırarak): ")
    key = input("Şifre çözme için bir anahtar girin (32 karaktere kadar): ")
    try:
        decrypted_text = decrypt(encrypted_text, key)
        print("\n Çözülmüş Metin:", decrypted_text)
    except Exception as e:
        print(f"Bir hata oluştu: {e}")


def main():
    while True:
        print("\nAES Şifreleme ve Çözme")
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