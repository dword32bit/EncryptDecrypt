import PySimpleGUI as sg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os
import base64

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalnum():
            if char.isalpha():
                shifted = ord(char) + shift
                if char.islower():
                    if shifted > ord('z'):
                        shifted -= 26
                    elif shifted < ord('a'):
                        shifted += 26
                elif char.isupper():
                    if shifted > ord('Z'):
                        shifted -= 26
                    elif shifted < ord('A'):
                        shifted += 26
                result += chr(shifted)
            elif char.isdigit():
                shifted = ord(char) + shift
                if shifted > ord('9'):
                    shifted -= 10
                elif shifted < ord('0'):
                    shifted += 10
                result += chr(shifted)
        else:
            result += char
    return result

def aes_encrypt(text, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_text).decode('utf-8')

def aes_decrypt(encrypted_text, password):
    encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    cipher_text = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()
    return decrypted_text.decode('utf-8')

def rsa_encrypt(text, public_key):
    encrypted_text = public_key.encrypt(
        text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_text).decode('utf-8')

def rsa_decrypt(encrypted_text, private_key):
    encrypted_data = base64.b64decode(encrypted_text.encode('utf-8'))
    decrypted_text = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text.decode('utf-8')

def load_public_key(file_path):
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

def load_private_key(file_path):
    with open(file_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def save_public_key(public_key, file_path):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(file_path, 'wb') as pem_out:
        pem_out.write(pem)

def save_private_key(private_key, file_path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(file_path, 'wb') as pem_out:
        pem_out.write(pem)

sg.theme('LightGrey1')

layout = [
    [sg.Text('Encryption/Decryption Tool', size=(40, 1), font=('Helvetica', 20))],
    [sg.Text('Select Algorithm:')],
    [sg.Radio('Caesar', 'RADIO1', default=True, key='-CAESAR-', enable_events=True),
     sg.Radio('AES', 'RADIO1', key='-AES-', enable_events=True),
     sg.Radio('RSA', 'RADIO1', key='-RSA-', enable_events=True)],
    [sg.Text('Operation:'), sg.Radio('Encrypt', 'RADIO2', default=True, key='-ENCRYPT-', enable_events=True),
     sg.Radio('Decrypt', 'RADIO2', key='-DECRYPT-', enable_events=True)],
    [sg.Text('Text to Encrypt/Decrypt:'), sg.InputText(key='-TEXT-')],
    [sg.Text('Shift (0-25):'), sg.Slider(range=(0, 25), orientation='h', size=(20, 15), default_value=3, key='-SHIFT-')],
    [sg.Text('Password:'), sg.InputText(key='-PASSWORD-', password_char='*')],
    [sg.Text('Public Key File:'), sg.InputText(key='-PUBKEY-'), sg.FileBrowse()],
    [sg.Text('Private Key File:'), sg.InputText(key='-PRIVKEY-'), sg.FileBrowse()],
    [sg.Button('Generate RSA Keys'), sg.Button('Save Public Key'), sg.Button('Save Private Key')],
    [sg.Button('Process'), sg.Button('Clear'), sg.Button('Exit')],
    [sg.Multiline('', size=(60, 10), key='-OUTPUT-')]
]

window = sg.Window('Encryption/Decryption Tool', layout, resizable=False)

# RSA Key variables
private_key = None
public_key = None

while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == 'Exit':
        break
    if event == 'Clear':
        window['-TEXT-'].update('')
        window['-OUTPUT-'].update('')
    if event == 'Generate RSA Keys':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        window['-OUTPUT-'].print("[RSA Key Generation] Keys generated successfully.")
    if event == 'Save Public Key':
        if public_key:
            save_path = sg.popup_get_file('Save Public Key', save_as=True, no_window=True)
            if save_path:
                save_public_key(public_key, save_path)
                window['-OUTPUT-'].print(f"[Save Public Key] Public key saved to {save_path}.")
        else:
            sg.popup_error("Public key is not generated or loaded.")
    if event == 'Save Private Key':
        if private_key:
            save_path = sg.popup_get_file('Save Private Key', save_as=True, no_window=True)
            if save_path:
                save_private_key(private_key, save_path)
                window['-OUTPUT-'].print(f"[Save Private Key] Private key saved to {save_path}.")
        else:
            sg.popup_error("Private key is not generated or loaded.")
    if event == 'Process':
        text = values['-TEXT-']
        shift = int(values['-SHIFT-'])
        password = values['-PASSWORD-']
        pubkey_file = values['-PUBKEY-']
        privkey_file = values['-PRIVKEY-']
        try:
            if values['-CAESAR-']:
                if values['-ENCRYPT-']:
                    result = caesar_cipher(text, shift)
                    info = f"[Caesar Cipher] [Characters shifted: +{shift}]"
                elif values['-DECRYPT-']:
                    result = caesar_cipher(text, -shift)
                    info = f"[Caesar Cipher] [Characters shifted: -{shift}]"
            elif values['-AES-']:
                if values['-ENCRYPT-']:
                    result = aes_encrypt(text, password)
                    info = "[AES Encryption]"
                elif values['-DECRYPT-']:
                    result = aes_decrypt(text, password)
                    info = "[AES Decryption]"
            elif values['-RSA-']:
                if values['-ENCRYPT-']:
                    if pubkey_file:
                        public_key = load_public_key(pubkey_file)
                        result = rsa_encrypt(text, public_key)
                        info = "[RSA Encryption] [Public Key Used]"
                    else:
                        raise ValueError("Public key file is required for RSA encryption.")
                elif values['-DECRYPT-']:
                    if privkey_file:
                        private_key = load_private_key(privkey_file)
                        result = rsa_decrypt(text, private_key)
                        info = "[RSA Decryption] [Private Key Used]"
                    else:
                        raise ValueError("Private key file is required for RSA decryption.")
            window['-OUTPUT-'].print(info + ' Result: ' + result)
        except Exception as e:
            sg.popup_error(f"An error occurred: {e}")

window.close()
