from cryptography.fernet import Fernet
from flask import Flask, render_template_string, render_template, jsonify
from flask import render_template
from flask import json
from urllib.request import urlopen
import sqlite3
                                                                                                                                       
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

@app.route('/decrypt/<string:token>')
def decryptage(token):
    try:
        token_decoded = urllib.parse.unquote_plus(token)
        decrypted_bytes = f.decrypt(token_decoded.encode())
        decrypted = decrypted_bytes.decode()
        return f"Valeur décryptée : {decrypted}"
    except Exception as e:
        return f"Erreur lors du déchiffrement : {str(e)}"

@app.route('/encrypt_personal', methods=['GET', 'POST'])
def encrypt_personal():
    if request.method == 'POST':
        valeur = request.form['valeur']
        user_key = request.form['key']

        try:
            # Valider et convertir la clé saisie
            key_bytes = base64.urlsafe_b64decode(user_key.encode())
            f = Fernet(base64.urlsafe_b64encode(key_bytes))
            token = f.encrypt(valeur.encode())
            return f"Texte chiffré : {token.decode()}"
        except Exception as e:
            return f"Erreur : clé invalide ou autre problème ({str(e)})"

    return render_template('encrypt_form.html')

@app.route('/decrypt_personal', methods=['GET', 'POST'])
def decrypt_personal():
    if request.method == 'POST':
        token = request.form['token']
        user_key = request.form['key']

        try:
            key_bytes = base64.urlsafe_b64decode(user_key.encode())
            f = Fernet(base64.urlsafe_b64encode(key_bytes))
            valeur = f.decrypt(token.encode()).decode()
            return f"Texte déchiffré : {valeur}"
        except InvalidToken:
            return "Erreur : Token ou clé invalide"
        except Exception as e:
            return f"Erreur : {str(e)}"

    return render_template('decrypt_form.html')


                                                                                                                                                     
if __name__ == "__main__":
  app.run(debug=True)
