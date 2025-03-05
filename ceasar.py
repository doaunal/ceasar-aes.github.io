def caesar_encrypt(text, shift, alphabet):
    encrypted_text = ""
    alphabet_size = len(alphabet)

    for char in text:
        if char in alphabet:
            new_index = (alphabet.index(char) + shift) % alphabet_size
            encrypted_text += alphabet[new_index]
        else:
            encrypted_text += char  
    return encrypted_text

def caesar_decrypt_all(text, alphabet):
    alphabet_size = len(alphabet)
    possible_solutions = []

   
    for shift in range(1, alphabet_size):  
        decrypted_text = caesar_encrypt(text, -shift, alphabet)
        possible_solutions.append(f"Kaydırma {shift}: {decrypted_text}")

    return possible_solutions


turkish_alphabet =  "abcçdefgğhıijklmnoöprsştuüvyz"

while True:
    choice = input("Şifreleme yapmak için 'E', çözme yapmak için 'D' girin (Çıkış için 'Q'): ").upper()
    
    if choice == 'E': 
        plain_text = input("Şifrelemek istediğiniz metni girin: ")
        shift_value = int(input("Kaydırma (shift) değerini girin: "))  
        encrypted_text = caesar_encrypt(plain_text, shift_value, turkish_alphabet)
        print("\n Şifreli Metin:", encrypted_text, "\n")

    elif choice == 'D':  
        encrypted_text = input("Çözmek istediğiniz şifreli metni girin: ")
        possible_decrypts = caesar_decrypt_all(encrypted_text, turkish_alphabet)

        print("\n Olası Çözümler:")
        for solution in possible_decrypts:
            print(solution)
        print()

    elif choice == 'Q':  
        print("Çıkış yapılıyor...")
        break
    
    else:
        print("Geçersiz seçim! Lütfen 'E', 'D' veya 'Q' girin.\n")