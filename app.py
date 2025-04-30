from flask import Flask, render_template, request, flash, session, redirect, url_for
from flask_session import Session
from flask_talisman import Talisman
from pqc.kem import kyber512 as kemalg
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from redis import Redis
from dotenv import load_dotenv
from datetime import timedelta
import base64
import os

# --- Load environment variables ---
load_dotenv()

app = Flask(__name__)
Talisman(app)

# --- Secure Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = Redis(host='redis', port=6379)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
Session(app)

# --- Helpers ---
def encode_key(key_bytes):
    return base64.b64encode(key_bytes).decode()

def decode_key(key_str):
    return base64.b64decode(key_str)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = ''
    decrypted_message = ''
    kem_ciphertext_b64 = ''

    # Key generation via button
    if request.method == 'POST' and 'generate_keys' in request.form:
        public_key, secret_key = kemalg.keypair()
        session['public_key'] = encode_key(public_key)
        session['secret_key'] = encode_key(secret_key)
        flash('New keys generated.', 'success')
        return redirect(url_for('index'))

    # If session keys are not yet generated
    if 'public_key' not in session or 'secret_key' not in session:
        public_key, secret_key = kemalg.keypair()
        session['public_key'] = encode_key(public_key)
        session['secret_key'] = encode_key(secret_key)

    public_key = decode_key(session['public_key'])
    secret_key = decode_key(session['secret_key'])

    if request.method == 'POST':
        if 'encrypt' in request.form:
            try:
                message = request.form['message'].encode()
                shared_secret, kem_ciphertext = kemalg.encap(public_key)
                aes_key = shared_secret[:32]
                iv = os.urandom(16)

                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                ciphertext = cipher.encrypt(pad(message, AES.block_size))

                kem_ciphertext_b64 = base64.b64encode(kem_ciphertext).decode()
                encrypted_message = base64.b64encode(iv + ciphertext).decode()
                flash('Message encrypted successfully!', 'success')
            except Exception:
                flash('Encryption failed.', 'danger')

        elif 'decrypt' in request.form:
            try:
                encrypted_message_bytes = base64.b64decode(request.form['encrypted_message'])
                kem_ciphertext_bytes = base64.b64decode(request.form['kem_ciphertext'])

                iv = encrypted_message_bytes[:16]
                ciphertext = encrypted_message_bytes[16:]

                shared_secret = kemalg.decap(kem_ciphertext_bytes, secret_key)
                aes_key = shared_secret[:32]

                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                decrypted_message_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
                decrypted_message = decrypted_message_bytes.decode()
                flash('Message decrypted successfully!', 'success')
            except Exception:
                flash('Decryption failed. Please check your inputs.', 'danger')

    return render_template('index.html',
                           public_key=session['public_key'],
                           secret_key=session['secret_key'],
                           encrypted_message=encrypted_message,
                           decrypted_message=decrypted_message,
                           kem_ciphertext=kem_ciphertext_b64)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)