from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_talisman import Talisman
from pqc.kem import kyber512 as kemalg
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
Talisman(app)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')

# Global Keys (for demo)
# public_key, secret_key = kemalg.keypair()

# @app.route('/', methods=['GET', 'POST'])
# def index():
#     encrypted_message = ''
#     decrypted_message = ''
#     kem_ciphertext_b64 = ''

#     if request.method == 'POST':
#         if 'encrypt' in request.form:
#             message = request.form['message'].encode()

#             # Step 1: Key Encapsulation (generate shared secret)
#             shared_secret, kem_ciphertext = kemalg.encap(public_key)
#             kem_ciphertext_b64 = base64.b64encode(kem_ciphertext).decode()

#             # Step 2: Encrypt message using AES with shared secret
#             aes_key = shared_secret[:32]  # AES-256
#             iv = os.urandom(16)

#             cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#             ciphertext = cipher.encrypt(pad(message, AES.block_size))

#             encrypted_message = base64.b64encode(iv + ciphertext).decode()

#             flash('Message encrypted successfully!', 'success')

#         elif 'decrypt' in request.form:
#             encrypted_message_input = request.form['encrypted_message']
#             kem_ciphertext_input = request.form['kem_ciphertext']

#             try:
#                 encrypted_message_bytes = base64.b64decode(encrypted_message_input)
#                 kem_ciphertext_bytes = base64.b64decode(kem_ciphertext_input)

#                 iv = encrypted_message_bytes[:16]
#                 ciphertext = encrypted_message_bytes[16:]

#                 # Step 1: Decapsulate to get shared secret
#                 shared_secret = kemalg.decap(kem_ciphertext_bytes, secret_key)

#                 # Step 2: AES decrypt
#                 aes_key = shared_secret[:32]
#                 cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#                 decrypted_message_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
#                 decrypted_message = decrypted_message_bytes.decode()

#                 flash('Message decrypted successfully!', 'success')
#             except Exception as e:
#                 flash('Decryption failed: ' + str(e), 'danger')

#     return render_template('index.html',
#                       encrypted_message=encrypted_message,
#                       decrypted_message=decrypted_message,
#                       kem_ciphertext=kem_ciphertext_b64,
#                       public_key=base64.b64encode(public_key).decode(),
#                       secret_key=base64.b64encode(secret_key).decode())

# @app.route('/', methods=['GET', 'POST'])
# def index():
#     encrypted_message = ''
#     decrypted_message = ''
#     kem_ciphertext_b64 = ''
#     display_public_key = ''
#     display_secret_key = ''

#     global public_key, secret_key  # keep the same keypair unless regenerated

#     if request.method == 'POST':
#         if 'generate_key' in request.form:
#             public_key, secret_key = kemalg.keypair()
#             flash("New key pair generated successfully!", "success")
#             display_public_key = base64.b64encode(public_key).decode()
#             display_secret_key = base64.b64encode(secret_key).decode()

#         elif 'encrypt' in request.form:
#             message = request.form['message'].encode()

#             shared_secret, kem_ciphertext = kemalg.encap(public_key)
#             kem_ciphertext_b64 = base64.b64encode(kem_ciphertext).decode()

#             aes_key = shared_secret[:32]
#             iv = os.urandom(16)

#             cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#             ciphertext = cipher.encrypt(pad(message, AES.block_size))
#             encrypted_message = base64.b64encode(iv + ciphertext).decode()

#             flash('Message encrypted successfully!', 'success')

#         elif 'decrypt' in request.form:
#             encrypted_message_input = request.form['encrypted_message']
#             kem_ciphertext_input = request.form['kem_ciphertext']

#             try:
#                 encrypted_message_bytes = base64.b64decode(encrypted_message_input)
#                 kem_ciphertext_bytes = base64.b64decode(kem_ciphertext_input)

#                 iv = encrypted_message_bytes[:16]
#                 ciphertext = encrypted_message_bytes[16:]

#                 shared_secret = kemalg.decap(kem_ciphertext_bytes, secret_key)

#                 aes_key = shared_secret[:32]
#                 cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#                 decrypted_message_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
#                 decrypted_message = decrypted_message_bytes.decode()

#                 flash('Message decrypted successfully!', 'success')
#             except Exception as e:
#                 flash('Decryption failed: ' + str(e), 'danger')

#     return render_template('index.html',
#                           encrypted_message=encrypted_message,
#                           decrypted_message=decrypted_message,
#                           kem_ciphertext=kem_ciphertext_b64,
#                           public_key=display_public_key,
#                           secret_key=display_secret_key)


# Session System for Constant Key Display
# @app.route('/', methods=['GET', 'POST'])
# def index():
#     encrypted_message = ''
#     decrypted_message = ''
#     kem_ciphertext_b64 = ''
#     public_key_display = ''
#     private_key_display = ''

#     if request.method == 'POST':
#         if 'generate' in request.form:
#             public_key, secret_key = kemalg.keypair()
#             session['public_key'] = base64.b64encode(public_key).decode()
#             session['secret_key'] = base64.b64encode(secret_key).decode()
#             flash('Key pair generated!', 'success')

#         elif 'encrypt' in request.form:
#             if 'public_key' not in session:
#                 flash('Please generate keys first.', 'danger')
#                 return redirect(url_for('index'))

#             public_key = base64.b64decode(session['public_key'])
#             message = request.form['message'].encode()

#             shared_secret, kem_ciphertext = kemalg.encap(public_key)
#             kem_ciphertext_b64 = base64.b64encode(kem_ciphertext).decode()

#             aes_key = shared_secret[:32]
#             iv = os.urandom(16)
#             cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#             ciphertext = cipher.encrypt(pad(message, AES.block_size))
#             encrypted_message = base64.b64encode(iv + ciphertext).decode()

#             flash('Message encrypted successfully!', 'success')

#         elif 'decrypt' in request.form:
#             if 'secret_key' not in session:
#                 flash('Please generate keys first.', 'danger')
#                 return redirect(url_for('index'))

#             secret_key = base64.b64decode(session['secret_key'])
#             try:
#                 encrypted_message_input = request.form['encrypted_message']
#                 kem_ciphertext_input = request.form['kem_ciphertext']

#                 encrypted_message_bytes = base64.b64decode(encrypted_message_input)
#                 kem_ciphertext_bytes = base64.b64decode(kem_ciphertext_input)

#                 iv = encrypted_message_bytes[:16]
#                 ciphertext = encrypted_message_bytes[16:]

#                 shared_secret = kemalg.decap(kem_ciphertext_bytes, secret_key)
#                 aes_key = shared_secret[:32]
#                 cipher = AES.new(aes_key, AES.MODE_CBC, iv)
#                 decrypted_message_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
#                 decrypted_message = decrypted_message_bytes.decode()

#                 flash('Message decrypted successfully!', 'success')
#             except Exception as e:
#                 flash('Decryption failed: ' + str(e), 'danger')

#     # For display
#     if 'public_key' in session:
#         public_key_display = session['public_key']
#     if 'secret_key' in session:
#         private_key_display = session['secret_key']

#     return render_template('index.html',
#                           encrypted_message=encrypted_message,
#                           decrypted_message=decrypted_message,
#                           kem_ciphertext=kem_ciphertext_b64,
#                           public_key_display=public_key_display,
#                           private_key_display=private_key_display)
@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = ''
    decrypted_message = ''
    kem_ciphertext_b64 = ''
    public_key_display = ''
    private_key_display = ''

    # Flag to control key display
    display_keys = False

    if request.method == 'POST':
        if 'generate' in request.form:
            public_key, secret_key = kemalg.keypair()
            session['public_key'] = base64.b64encode(public_key).decode()
            session['secret_key'] = base64.b64encode(secret_key).decode()
            session['keys_generated'] = True  # 👈 Add flag
            flash('Key pair generated!', 'success')

        elif 'encrypt' in request.form:
            if 'public_key' not in session:
                flash('Please generate keys first.', 'danger')
                return redirect(url_for('index'))

            public_key = base64.b64decode(session['public_key'])
            message = request.form['message'].encode()

            shared_secret, kem_ciphertext = kemalg.encap(public_key)
            kem_ciphertext_b64 = base64.b64encode(kem_ciphertext).decode()

            aes_key = shared_secret[:32]
            iv = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(message, AES.block_size))
            encrypted_message = base64.b64encode(iv + ciphertext).decode()

            flash('Message encrypted successfully!', 'success')

        elif 'decrypt' in request.form:
            if 'secret_key' not in session:
                flash('Please generate keys first.', 'danger')
                return redirect(url_for('index'))

            secret_key = base64.b64decode(session['secret_key'])
            try:
                encrypted_message_input = request.form['encrypted_message']
                kem_ciphertext_input = request.form['kem_ciphertext']

                encrypted_message_bytes = base64.b64decode(encrypted_message_input)
                kem_ciphertext_bytes = base64.b64decode(kem_ciphertext_input)

                iv = encrypted_message_bytes[:16]
                ciphertext = encrypted_message_bytes[16:]

                shared_secret = kemalg.decap(kem_ciphertext_bytes, secret_key)
                aes_key = shared_secret[:32]
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                decrypted_message_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
                decrypted_message = decrypted_message_bytes.decode()

                flash('Message decrypted successfully!', 'success')
            except Exception as e:
                flash('Decryption failed: ' + str(e), 'danger')

    # ✅ Only display keys if user has clicked "Generate Key"
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
    app.run(debug=True)
