from faker import Faker
class FakeDataGenerator:
    def __init__(self, language='en'):
        self.fake = Faker(language)

    def generate_data(self):
        return self.fake.name()

from requests import get
from bs4 import BeautifulSoup
class WebsiteReader:
    def __init__(self, url, search_word):
        self.url = url
        self.search_word = search_word

    def get_source_code(self):
        response = get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.prettify()

    def get_word_locations(self):
        source_code = self.get_source_code()
        return [i for i in range(len(source_code)) if source_code.startswith(self.search_word, i)]

from cryptography.fernet import Fernet
import hashlib
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
