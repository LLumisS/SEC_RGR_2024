import socket
import secrets
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SERVER_HOST = "localhost"
SERVER_PORT = 8443

CA_HOST = "localhost"
CA_PORT = 8444

SALT = b"security_labs"


def generate_session_key(premaster_secret, client_hello, server_hello):
    key_material = premaster_secret + client_hello + server_hello

    # Генерація сеансового ключа з використанням PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    
    return kdf.derive(key_material)

def encrypt_message(session_key, message):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_message(session_key, encrypted_message):
    iv = encrypted_message[:12]
    tag = encrypted_message[12:28]
    ciphertext = encrypted_message[28:]

    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()


def verify_certificate(server_cert):
    ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_socket.connect((CA_HOST, CA_PORT))
    
    ca_socket.send("CLIENT_VERIFY".encode() + b"\n" + server_cert.public_bytes(serialization.Encoding.PEM))
    is_valid = ca_socket.recv(4096).decode()
    ca_socket.close()
    
    return is_valid


# Клієнт
def run_client():
    # Генерація випадкових даних клієнта
    client_hello = secrets.token_hex(16).encode()

    # Підключення до сервера
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print("Підключено до сервера.")

    # Відправлення привітання
    client_socket.send(client_hello)
    print("Клієнт надіслав привітання.")

    # Отримання відповіді та сертифіката
    server_hello, server_cert = client_socket.recv(4096).split(b"\n", 1)
    print(f"Клієнт отримав привітання.")
    server_cert = load_pem_x509_certificate(server_cert)

    # Перевірка сертифіката
    if not verify_certificate(server_cert):
        print("Сертифікат не пройшов верифікацію.")
        client_socket.close()
        return

    # Генерація premaster і шифрування
    premaster_secret = secrets.token_hex(16).encode()
    encrypted_premaster = server_cert.public_key().encrypt(
        premaster_secret,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    client_socket.send(encrypted_premaster)
    print("Клієнт надіслав premaster секрет.")

    # Готовність
    session_key = generate_session_key(premaster_secret, client_hello, server_hello)

    message = client_socket.recv(4096)
    decrypted_message = decrypt_message(session_key, message)
    print(f"Сервер відповів: {decrypted_message}.")

    encrypted_message = encrypt_message(session_key, "Готовий")
    client_socket.send(encrypted_message)

    print("Рукостискання завершено.")

if __name__ == "__main__":
    run_client()
