from faker import Faker
import requests
from cryptography.fernet import Fernet
import hashlib
import socket
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog

class AppGUI:
    def __init__(self, root):
        self.root = root
        self.create_widgets()

    def create_widgets(self):
        self.generate_fake_data_button = tk.Button(self.root, text="Generate fake data", command=self.generate_fake_data)
        self.read_website_button = tk.Button(self.root, text="Read a website", command=self.read_website)
        self.encrypt_string_button = tk.Button(self.root, text="Encrypt a string", command=self.encrypt_string)
        self.decrypt_string_button = tk.Button(self.root, text="Decrypt a string with Caesar Cipher", command=self.decrypt_string)
        self.decrypt_vigenere_button = tk.Button(self.root, text="Decrypt a string with Vigenere Cipher", command=self.decrypt_vigenere)
        self.ddos_button = tk.Button(self.root, text="DDOS Attack", command=self.ddos)
        self.mssp_decryptor_button = tk.Button(self.root, text="MSSP Decryptor", command=self.mssp_decryptor)
        self.exit_button = tk.Button(self.root, text="Exit", command=self.exit_app)

        self.generate_fake_data_button.pack()
        self.read_website_button.pack()
        self.encrypt_string_button.pack()
        self.decrypt_string_button.pack()
        self.decrypt_vigenere_button.pack()
        self.ddos_button.pack()
        self.mssp_decryptor_button.pack()
        self.exit_button.pack()

    def generate_fake_data(self):
        language = simpledialog.askstring("Language", "Please enter a language (en_US, it_IT, ja_JP, he_IL):")
        if language in ['en_US', 'it_IT', 'ja_JP', 'he_IL']:
            fakeData = FakeDataGenerator(language)
            messagebox.showinfo("Result", fakeData.generate_data())
        else:
            messagebox.showerror("Error", "Invalid language input")

    def read_website(self):
        url = simpledialog.askstring("URL", "Please enter a URL:")
        search_word = simpledialog.askstring("Search Word", "Please enter a search word:")
        websiteReader = WebsiteReader(url, search_word)
        result = websiteReader.get_word_locations(search_word)
        messagebox.showinfo("Result", result)

    def encrypt_string(self):
        encryption_method = simpledialog.askinteger("Encryption Method", "Please enter an encryption method:\n1. SHA256\n2. Fernet")
        if encryption_method == 1:
            user_input = simpledialog.askstring("String", "Please enter a string to encrypt:")
            stringEncryptor = StringEncryptor(user_input)
            messagebox.showinfo("Result", stringEncryptor.sha256_encrypt())
        elif encryption_method == 2:
            user_input = simpledialog.askstring("String", "Please enter a string to encrypt:")
            stringEncryptor = StringEncryptor(user_input)
            messagebox.showinfo("Result", stringEncryptor.fernet_encrypt())
        else:
            messagebox.showerror("Error", "Invalid encryption method input")

    def decrypt_string(self):
        encrypted_text = simpledialog.askstring("Encrypted Text", "Please enter a string to decrypt:")
        caesarCipher = CaesarCipher(encrypted_text)
        caesarCipher.decrypt()

    def decrypt_vigenere(self):
        encrypted_text = simpledialog.askstring("Encrypted Text", "Please enter a string to decrypt:")
        vigenereCipher = VigenereCipher(encrypted_text)
        vigenereCipher.decrypt_with_all_keys()

    def ddos(self):
        ip = simpledialog.askstring("IP Address", "Please enter an IP address:")
        port = simpledialog.askinteger("Port", "Please enter a port number:")
        msg = simpledialog.askstring("Message", "Please enter a message:")
        thread_count = simpledialog.askinteger("Thread Count", "Please enter the number of threads:")
        threads = []
        for i in range(thread_count):
            thread = DDOS(i, "Thread-" + str(i), i, ip, port, msg)
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def mssp_decryptor(self):
        ciphertext = simpledialog.askstring("Ciphertext", "Please enter a ciphertext:")
        n_input = simpledialog.askstring("n", "Please enter n (leave blank to calculate it):")
        n = int(n_input) if n_input else None
        m_input = simpledialog.askstring("m", "Please enter m (leave blank to calculate it):")
        m = int(m_input) if m_input else None
        d_input = simpledialog.askstring("d", "Please enter d (leave blank to calculate it):")
        d = int(d_input) if d_input else None
        msspDecryptor = MSSPDecryptor(ciphertext, n, m, d)
        messagebox.showinfo("Result", msspDecryptor.decrypt())

    def exit_app(self):
        self.root.quit()

class FakeDataGenerator:
    def __init__(self, language='en_US'):
        self.fake = Faker(language)

    def generate_data(self):
        return [self.fake.name() , self.fake.address() , self.fake.text()]

    def language(self, lan):
        if lan == 'en_US' or lan == 'it_IT' or lan == 'ja_JP' or lan == 'he_IL':
            self.fake = Faker(lan)
            return True
        else:
            return False

class WebsiteReader:
    def __init__(self, url, search_word=None):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        self.url = url
        self.search_word = search_word
        self.lst= []
        self.resultText = self.get_source_code()

    def get_source_code(self):
        result = requests.get(self.url)
        self.resultText = result.text
        return self.resultText

    def get_word_locations(self,text):
        for i in range (0, len(self.resultText)):
            resultSub=self.resultText.find(text,i,i+len(text))
            if resultSub != -1:
                self.lst.append(resultSub)
                i=i+len(text)
        return self.lst

class StringEncryptor:
    def __init__(self, user_input):
        self.user_input = user_input.encode()

    def sha256_encrypt(self):
        return hashlib.sha256(self.user_input).hexdigest()

    def fernet_encrypt(self):
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        cipher_text = cipher_suite.encrypt(self.user_input)
        return cipher_text

class CaesarCipher:
    def __init__(self, encrypted_text):
        self.encrypted_text = encrypted_text

    def decrypt(self):
        for shift in range(26):
            decrypted_text = ""
            for char in self.encrypted_text:
                if char.isalpha():
                    ascii_offset = ord('a') if char.islower() else ord('A')
                    decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                    decrypted_text += decrypted_char
                else:
                    decrypted_text += char
            print(f'Shift {shift}: {decrypted_text}')

class VigenereCipher:
    def __init__(self, encrypted_text):
        self.encrypted_text = encrypted_text
        self.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    def decrypt(self, key):
        decrypted_text = ""
        key_length = len(key)
        for i, char in enumerate(self.encrypted_text):
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                shift = ord(key[i % key_length]) - ascii_offset
                decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        return decrypted_text

    def decrypt_with_all_keys(self):
        for i in range(26):
            key = ''.join([self.alphabet[(self.alphabet.index(c) + i) % 26] for c in self.alphabet])
            print(f'Key: {key}, Decrypted text: {self.decrypt(key)}')

class DDOS(threading.Thread):
    def __init__(self, threadID, name, counter, ip, port, msg):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.ip = ip
        self.port = port
        self.msg = msg

    def attack(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        server_address = (self.ip, self.port)
        print(sys.stderr, 'connecting to %s port %s' % server_address)
        sock.connect(server_address)
        try:
            # Send data
            threadmsg = 'Thread-', self.threadID, ':', self.msg;
            message = str.encode(str(threadmsg))
            print(sys.stderr, 'thread-', self.threadID, 'sending "%s"' % message)
            sock.sendall(message)
            # Look for the response
            amount_received = 0
            amount_expected = len(message)
            while amount_received < amount_expected:
                data = sock.recv(16)
                amount_received += len(data)
                print(sys.stderr, 'received "%s"' % data)
        finally:
            print(sys.stderr, 'closing socket')
            sock.close()

    def run(self):
        print("Starting " + self.name)
        self.attack()
        print("Exiting " + self.name)

class MSSPDecryptor:
    def __init__(self, ciphertext, n=None, m=None, d=None):
        self.ciphertext = ''.join(char for char in ciphertext if char.isdigit())
        self.n = n
        self.m = m
        self.d = d

    def decrypt(self):
        # Calculate the missing parameter
        if self.n is None:
            self.n = len(self.ciphertext) // (self.m * self.d)
        elif self.m is None:
            self.m = len(self.ciphertext) // (self.n * self.d)
        else:  # self.d is None
            self.d = len(self.ciphertext) // (self.n * self.m)

        # Split the ciphertext into n sets
        sets = [self.ciphertext[i:i + self.d * self.m] for i in range(0, len(self.ciphertext), self.d * self.m)]

        # Check that we have the correct number of sets
        if len(sets) != self.n:
            raise ValueError("Ciphertext cannot be evenly divided into n sets of m items of d digits")

        # Split each set into m items of d digits
        sets = [[int(set[i:i + self.d]) for i in range(0, len(set), self.d)] for set in sets]

        # Find a common sum in all sets
        common_sum = self.find_common_sum(sets)

        # Return the common sum
        return common_sum

    def find_common_sum(self, sets):
        # Try all possible sums from the sum of the first set down to 0
        for target_sum in range(sum(sets[0]), -1, -1):
            # Check if this sum can be made by a subset of each set
            if all(self.calcSubsetSum(set, target_sum) for set in sets):
                # If it can, return this sum
                return target_sum
        # If no common sum is found, raise an error
        raise ValueError("No common sum found in all sets")

    def calcSubsetSum(self, nums, sum):
        if sum == 0:
            return True
        if not nums:
            return False
        return self.calcSubsetSum(nums[1:], sum - nums[0]) or self.calcSubsetSum(nums[1:], sum)

if __name__ == '__main__':
    # print("Welcome to the main program")
    # while(True):
    #     print("Please select an option:")
    #     print("1. Generate fake data")
    #     print("2. Read a website")
    #     print("3. Encrypt a string")
    #     print("4. Decrypt a string")
    #     print("5. Decrypt a string with Vigenere Cipher")
    #     print("6. DDOS")
    #     print("7. MSSP Decryptor")
    #     print("8. Exit")
    #     option = int(input("Please enter your option: "))
    #     if option == 1:
    #         print("Please select a language:")
    #         print("1. English")
    #         print("2. Italian")
    #         print("3. Japanese")
    #         print("4. Hebrew")
    #         language = int(input("Please enter your option: "))
    #         if language == 1:
    #             language = 'en_US'
    #         elif language == 2:
    #             language = 'it_IT'
    #         elif language == 3:
    #             language = 'ja_JP'
    #         elif language == 4:
    #             language = 'he_IL'
    #         else:
    #             print("Invalid input")
    #             exit(0)
    #         fakeData = FakeDataGenerator(language) # default language is English
    #         print(fakeData.generate_data())
    #     elif option == 2:
    #         url = input("Please enter a URL: ")
    #         search_word = input("Please enter a search word: ")
    #         websiteReader = WebsiteReader(url, search_word)
    #         print(websiteReader.get_word_locations(search_word))
    #     elif option == 3:
    #         print("Please select an encryption method:")
    #         print("1. SHA256")
    #         print("2. Fernet")
    #         encryption_method = int(input("Please enter your option: "))
    #         if encryption_method == 1:
    #             user_input = input("Please enter a string to encrypt: ")
    #             stringEncryptor = StringEncryptor(user_input)
    #             print(stringEncryptor.sha256_encrypt())
    #         elif encryption_method == 2:
    #             user_input = input("Please enter a string to encrypt: ")
    #             stringEncryptor = StringEncryptor(user_input)
    #             print(stringEncryptor.fernet_encrypt())
    #     elif option == 4:
    #         encrypted_text = input("Please enter a string to decrypt: ")
    #         caesarCipher = CaesarCipher(encrypted_text)
    #         caesarCipher.decrypt()
    #     elif option == 5:
    #         encrypted_text = input("Please enter a string to decrypt: ")
    #         vigenereCipher = VigenereCipher(encrypted_text)
    #         vigenereCipher.decrypt_with_all_keys()
    #     elif option == 6:
    #         ip = input("Please enter an IP address: ")
    #         port = int(input("Please enter a port number: "))
    #         msg = input("Please enter a message: ")
    #         thread_count = int(input("Please enter the number of threads: "))
    #         threads = []
    #         for i in range(thread_count):
    #             thread = DDOS(i, "Thread-" + str(i), i, ip, port, msg)
    #             threads.append(thread)
    #         for thread in threads:
    #             thread.start()
    #         for thread in threads:
    #             thread.join()
    #     elif option == 7:
    #         ciphertext = input("Please enter a ciphertext: ")
    #
    #         n_input = input("Please enter n: ")
    #         n = int(n_input) if n_input else None
    #
    #         m_input = input("Please enter m: ")
    #         m = int(m_input) if m_input else None
    #
    #         d_input = input("Please enter d: ")
    #         d = int(d_input) if d_input else None
    #
    #         msspDecryptor = MSSPDecryptor(ciphertext, n, m, d)
    #         print(msspDecryptor.decrypt())
    #
    #     elif option == 8:
    #         exit(0)
    #     else:
    #         print("Invalid input")
    #         exit(0)
    #     print('\n')

    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()
    root.mainloop()