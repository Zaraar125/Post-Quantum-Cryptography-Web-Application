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
import warnings
warnings.filterwarnings('ignore')

# --- Load environment variables ---
load_dotenv()

app = Flask(__name__)
Talisman(app)

# --- Secure Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'random_777_key!@#')
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = Redis(host='redis', port=6379)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
Session(app)

@app.before_request
def make_session_permanent():
    session.permanent = True

# --- Helpers ---
def encode_key(key_bytes):
    return base64.b64encode(key_bytes).decode()

def decode_key(key_str):
    return base64.b64decode(key_str)

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = ''
    decrypted_message = ''
    kem_ciphertext_b64 = ''
    public_key_display = ''
    private_key_display = ''

    if request.method == 'POST':
        if 'generate_keys' in request.form:
            public_key, secret_key = kemalg.keypair()
            session['public_key'] = encode_key(public_key)
            session['secret_key'] = encode_key(secret_key)
            session['keys_generated'] = True
            flash('Key pair generated!', 'success')
            return redirect(url_for('index'))

        elif 'encrypt' in request.form:
            if not session.get('keys_generated'):
                flash('Please generate keys first.', 'danger')
                return redirect(url_for('index'))

            try:
                public_key = decode_key(session['public_key'])
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
            if not session.get('keys_generated'):
                flash('Please generate keys first.', 'danger')
                return redirect(url_for('index'))

            try:
                secret_key = decode_key(session['secret_key'])
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
            except Exception as e:
                flash(f'Decryption failed: {str(e)}', 'danger')

    # Show keys only if generated
    if session.get('keys_generated'):
        public_key_display = session.get('public_key', '')
        private_key_display = session.get('secret_key', '')

    return render_template('index.html',
                           encrypted_message=encrypted_message,
                           decrypted_message=decrypted_message,
                           kem_ciphertext=kem_ciphertext_b64,
                           public_key_display=public_key_display,
                           private_key_display=private_key_display)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)