from faker import Faker
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
import hashlib
import socket
import sys
import threading
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
    def __init__(self, url, search_word):
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
    def __init__(self, ciphertext, n, m, d):
        self.ciphertext = ciphertext
        self.n = n
        self.m = m
        self.d = d

    def decrypt(self):
        # Split the ciphertext into n sets
        sets = [self.ciphertext[i:i + self.d * self.m] for i in range(0, len(self.ciphertext), self.d * self.m)]

        # Check that we have the correct number of sets
        if len(sets) != self.n:
            raise ValueError("Ciphertext cannot be evenly divided into n sets of m items of d digits")

        # Split each set into m items of d digits
        sets = [[set[i:i + self.d] for i in range(0, len(set), self.d)] for set in sets]

        # Convert each item to an integer and sum them
        sums = [sum(int(item) for item in set) for set in sets]

        # Check that all sums are equal
        if len(set(sums)) != 1:
            raise ValueError("Not all sets sum to the same value")

        # Return the sum
        return sums[0]


if __name__ == '__main__':
    print("Welcome to the main program")
    while(True):
        print("Please select an option:")
        print("1. Generate fake data")
        print("2. Read a website")
        print("3. Encrypt a string")
        print("4. Decrypt a string")
        print("5. Decrypt a string with Vigenere Cipher")
        print("6. DDOS")
        print("7. MSSP Decryptor")
        print("8. Exit")
        option = int(input("Please enter your option: "))
        if option == 1:
            print("Please select a language:")
            print("1. English")
            print("2. Italian")
            print("3. Japanese")
            print("4. Hebrew")
            language = int(input("Please enter your option: "))
            if language == 1:
                language = 'en_US'
            elif language == 2:
                language = 'it_IT'
            elif language == 3:
                language = 'ja_JP'
            elif language == 4:
                language = 'he_IL'
            else:
                print("Invalid input")
                exit(0)
            fakeData = FakeDataGenerator(language) # default language is English
            print(fakeData.generate_data())
        elif option == 2:
            url = input("Please enter a URL: ")
            search_word = input("Please enter a search word: ")
            websiteReader = WebsiteReader(url, search_word)
            print(websiteReader.get_word_locations(search_word))
        elif option == 3:
            print("Please select an encryption method:")
            print("1. SHA256")
            print("2. Fernet")
            encryption_method = int(input("Please enter your option: "))
            if encryption_method == 1:
                user_input = input("Please enter a string to encrypt: ")
                stringEncryptor = StringEncryptor(user_input)
                print(stringEncryptor.sha256_encrypt())
            elif encryption_method == 2:
                user_input = input("Please enter a string to encrypt: ")
                stringEncryptor = StringEncryptor(user_input)
                print(stringEncryptor.fernet_encrypt())
        elif option == 4:
            encrypted_text = input("Please enter a string to decrypt: ")
            caesarCipher = CaesarCipher(encrypted_text)
            caesarCipher.decrypt()
        elif option == 5:
            encrypted_text = input("Please enter a string to decrypt: ")
            vigenereCipher = VigenereCipher(encrypted_text)
            vigenereCipher.decrypt_with_all_keys()
        elif option == 6:
            ip = input("Please enter an IP address: ")
            port = int(input("Please enter a port number: "))
            msg = input("Please enter a message: ")
            thread_count = int(input("Please enter the number of threads: "))
            threads = []
            for i in range(thread_count):
                thread = DDOS(i, "Thread-" + str(i), i, ip, port, msg)
                threads.append(thread)
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        elif option == 7:
            ciphertext = input("Please enter a ciphertext: ")
            n = int(input("Please enter n: "))
            m = int(input("Please enter m: "))
            d = int(input("Please enter d: "))
            msspDecryptor = MSSPDecryptor(ciphertext, n, m, d)
            print(msspDecryptor.decrypt())
        elif option == 8:
            exit(0)
        else:
            print("Invalid input")
            exit(0)
        print('\n')