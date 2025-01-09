from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import CertificateBuilder, NameOID
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import random_serial_number
from cryptography import x509
import socket
import datetime

HOST = "localhost"
PORT = 8444

# Генерація ключа й сертифіката СА
def generate_ca_certificate():
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA Root"),
    ])

    ca_certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    return ca_private_key, ca_certificate

# Генерація сертифіката для сервера
def generate_server_certificate(public_server_key, ca_private_key, ca_certificate):
    public_server_key = serialization.load_pem_public_key(public_server_key)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    server_certificate = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_server_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    return server_certificate

# Верифікація сертифіката
def verify_certificate(client_cert, ca_certificate):
    try:
        ca_certificate.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Помилка верифікації: {e}")
        return False

def run_ca_server():
    ca_private_key, ca_certificate = generate_ca_certificate()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("Центр сертифікації очікує підключення...")

    while True:
        conn, addr = server_socket.accept()

        # Отримання запиту від клієнта або сервера
        request_type, data = conn.recv(4096).split(b"\n", 1)

        if request_type.decode() == "SERVER_REQUEST":
            print(f"Підключення від сервера.")
            # Генерація і відправка сертифіката серверу
            server_certificate = generate_server_certificate(data, ca_private_key, ca_certificate)
            conn.send(server_certificate.public_bytes(serialization.Encoding.PEM))
            print("Серверу відправлено сертифікат.")

        elif request_type.decode() == "CLIENT_VERIFY":
            print(f"Підключення від клієнта.")
            # Отримання сертифіката від клієнта
            client_cert = x509.load_pem_x509_certificate(data)

            # Верифікація отриманого сертифіката
            is_valid = verify_certificate(client_cert, ca_certificate)
            conn.send(b"VALID" if is_valid else b"INVALID")
            print("Сертифікат перевірено.")

        conn.close()

if __name__ == "__main__":
    run_ca_server()
