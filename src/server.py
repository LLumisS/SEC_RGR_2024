import socket
import secrets
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


HOST = "localhost"
PORT = 8443

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


def get_certificate(public_key):
    ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_socket.connect((CA_HOST, CA_PORT))
    
    ca_socket.send("SERVER_REQUEST".encode() + b"\n" + public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    server_cert = ca_socket.recv(4096)
    ca_socket.close()
    
    return server_cert


# Сервер
def run_server():
    # Генерація ключів
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    # Отримання сертифікату
    server_cert = get_certificate(public_key)

    # Запуск сервера
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("Сервер очікує з'єднання...")

    conn, addr = server_socket.accept()
    print(f"Підключено до клієнта.")

    # Відповідь на "привіт"
    client_hello = conn.recv(1024)
    print(f"Сервер отримав привітання.")

    server_hello = secrets.token_hex(16).encode()
    conn.send(server_hello + b"\n" + server_cert)
    print("Сервер надіслав привітання і сертифікат.")

    # Отримання секрету premaster
    encrypted_premaster = conn.recv(1024)
    server_cert = load_pem_x509_certificate(server_cert)
    premaster_secret = private_key.decrypt(
        encrypted_premaster,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print("Сервер отримав premaster секрет.")

    # Готовність
    session_key = generate_session_key(premaster_secret, client_hello, server_hello)

    encrypted_message = encrypt_message(session_key, "Готовий")
    conn.send(encrypted_message)

    message = conn.recv(4096)
    decrypted_message = decrypt_message(session_key, message)
    print(f"Клієнт відповів: {decrypted_message}.")

    print("Сервер завершив рукостискання.")

if __name__ == "__main__":
    run_server()
