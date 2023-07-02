from faker import Faker
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
import hashlib
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

if __name__ == '__main__':
    print("Welcome to the main program")
    print("Please select an option:")
    print("1. Generate fake data")
    print("2. Read a website")
    print("3. Encrypt a string")
    print("4. Exit")
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
        fakeData = FakeDataGenerator(language)
        print(fakeData.generate_data())
    elif option == 2:
        url = input("Please enter a URL: ")
        search_word = input("Please enter a search word: ")
        websiteReader = WebsiteReader(url, search_word)
        print(websiteReader.get_word_locations(search_word))
    elif option == 3:
        user_input = input("Please enter a string: ")
        stringEncryptor = StringEncryptor(user_input)
        print(stringEncryptor.sha256_encrypt())
        print(stringEncryptor.fernet_encrypt())
    elif option == 4:
        exit(0)
    else:
        print("Invalid input")
        exit(0)