from cryptography.fernet import Fernet
from flask import Flask, render_template_string, render_template, jsonify
from flask import render_template, request
from flask import json
from urllib.request import urlopen
import sqlite3
import urllib.parse


                                                                                                                                       
app = Flask(__name__)                                                                                                                  
                                                                                                                                       
@app.route('/')
def hello_world():
    return render_template('hello.html') #comm

key = Fernet.generate_key()
f = Fernet(key)


@app.route('/encrypt/<string:valeur>')
def encryptage(valeur):
    valeur_bytes = valeur.encode()  # Conversion str -> bytes
    token = f.encrypt(valeur_bytes)  # Encrypt la valeur
    return f"Valeur encryptée : {token.decode()}"  # Retourne le token en str


# EXO 1

@app.route('/decrypt/<string:token>')
def decryptage(token):
    try:
        token_decoded = urllib.parse.unquote_plus(token)
        decrypted_bytes = f.decrypt(token_decoded.encode())
        decrypted = decrypted_bytes.decode()
        return f"Valeur décryptée : {decrypted}"
    except Exception as e:
        return f"Erreur lors du déchiffrement : {str(e)}"

# EXO 2

@app.route('/encrypt_custom/<path:message>/<path:user_key>')
def encrypt_custom(message, user_key):
    try:
        fernet = Fernet(user_key.encode())
        encrypted = fernet.encrypt(message.encode()).decode()
        return f"Message chiffré : {encrypted}"
    except Exception as e:
        return f"Erreur lors du chiffrement : {str(e)}"


@app.route('/decrypt_custom/<path:token>/<path:user_key>')
def decrypt_custom(token, user_key):
    try:
        fernet = Fernet(user_key.encode())
        decrypted = fernet.decrypt(token.encode()).decode()
        return f"Message déchiffré : {decrypted}"
    except Exception as e:
        return f"Erreur lors du déchiffrement : {str(e)}"


                                                                                                                                                     
if __name__ == "__main__":
  app.run(debug=True)
