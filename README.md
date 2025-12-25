# Post-Quantum Cryptography Web Application

## Overview

This is a **Flask-based web application** that demonstrates **Post-Quantum Cryptography (PQC)** using the **Kyber512 Key Encapsulation Mechanism (KEM)** combined with **AES-256 encryption**. The application allows users to securely encrypt and decrypt messages using cryptographic algorithms designed to resist attacks from future quantum computers.

The application serves as both a **practical demonstration** and an **educational tool** for understanding how post-quantum cryptographic algorithms work in a real-world web context.

---

## What is Post-Quantum Cryptography?

Post-Quantum Cryptography refers to cryptographic algorithms that are believed to be secure against both classical and quantum computer attacks. Current widely-used encryption methods (like RSA) can be broken by sufficiently powerful quantum computers using Shor's algorithm. 

**Kyber512** is a lattice-based KEM standardized by NIST (National Institute of Standards and Technology) as part of their Post-Quantum Cryptography standardization project. It provides:
- **Quantum-resistant security**: Resistant to attacks from quantum computers
- **Efficient key exchange**: Practical for real-world applications
- **Standardized algorithm**: Approved by NIST for cryptographic use

---

## How This Application Works

### Cryptographic Flow

The application implements a two-layer encryption system:

1. **Key Generation (Kyber512 KEM)**
   - Generates a keypair: public key and secret key
   - Public key: 352 bytes (used for encryption)
   - Secret key: 1632 bytes (used for decryption)
   - Keys are Base64-encoded for safe display and storage in sessions

2. **Encryption Process**
   - User provides a plaintext message
   - Uses the public key to encapsulate a shared secret with Kyber512
   - Derives a 256-bit AES key from the first 32 bytes of the shared secret
   - Generates a random 128-bit IV (Initialization Vector)
   - Encrypts the message using **AES-256 in CBC mode** with PKCS7 padding
   - Returns: encrypted message (IV + ciphertext) and KEM ciphertext, both Base64-encoded

3. **Decryption Process**
   - User provides the encrypted message and KEM ciphertext
   - Uses the secret key to decapsulate the shared secret from the KEM ciphertext
   - Derives the same AES key (first 32 bytes of shared secret)
   - Extracts the IV from the encrypted message (first 16 bytes)
   - Decrypts the ciphertext using AES-256-CBC and removes PKCS7 padding
   - Returns the original plaintext message

### Security Features

- **Post-Quantum Secure**: Uses Kyber512, resistant to quantum computer attacks
- **Hybrid Encryption**: Combines asymmetric (Kyber512) with symmetric (AES-256) encryption
- **Session Management**: Keys are stored securely in server-side sessions with 15-minute expiration
- **Security Headers**: Flask-Talisman provides HTTP security headers (CSP, X-Frame-Options, etc.)
- **Error Handling**: Comprehensive exception handling and logging
- **HTTPS Support**: Ready for HTTPS deployment (disabled for local development)

---

## Technologies & Dependencies

| Component | Purpose |
|-----------|---------|
| **Python 3** | Programming language |
| **Flask** | Web framework for building the application |
| **pycryptodome** | AES encryption and padding utilities |
| **pypqc (pqc)** | Kyber512 post-quantum cryptographic algorithm |
| **Flask-Session** | Server-side session management (filesystem/Redis) |
| **Flask-Talisman** | Security headers and CORS management |
| **Redis** (optional) | Session storage backend for production |
| **python-dotenv** | Environment variable management |

---

## Project Structure

```
Post-Quantum-Cryptography-Web-Application/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
├── Dockerfile                      # Docker container setup
├── docker-compose.yaml             # Docker Compose for local deployment
├── README.md                       # This file
├── templates/
│   └── index.html                 # Web UI template
├── static/
│   └── style.css                  # Styling
└── flask_session/                  # Session storage (auto-generated)
```

---

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- (Optional) Docker and Docker Compose for containerized deployment

### Local Development Setup

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd Post-Quantum-Cryptography-Web-Application
   ```

2. **Create a Virtual Environment**
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate

   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create Environment File**
   ```bash
   # Copy the example file
   copy .env.example .env          # Windows
   cp .env.example .env             # macOS/Linux
   ```
   
   Edit `.env` and set a strong `SECRET_KEY`:
   ```
   SECRET_KEY=your_very_secret_key_here_with_special_chars!@#$%
   ```

5. **Run the Application**
   ```bash
   python app.py
   ```
   
   The application will be available at: `http://localhost:5000`

### Docker Setup

To run using Docker:

```bash
# Build and run with Docker Compose
docker-compose up --build

# Access at http://localhost:5000
```

---

## How to Use the Application

### Step 1: Generate Keys
1. Click the **"Generate Keys"** button
2. This creates a new Kyber512 keypair
3. Your public and secret keys will be displayed and stored in the session
4. **Note**: Keys are stored in the server session and expire after 15 minutes of inactivity

### Step 2: Encrypt a Message
1. Enter your plaintext message in the "Message to Encrypt" field
2. Click the **"Encrypt"** button
3. The application will:
   - Use your public key to encapsulate a shared secret
   - Derive an AES-256 key from the shared secret
   - Encrypt your message using AES-256-CBC
4. Two outputs are displayed:
   - **Encrypted Message**: The encrypted data (Base64-encoded)
   - **KEM Ciphertext**: The encapsulated shared secret (Base64-encoded)

### Step 3: Decrypt a Message
1. Paste your encrypted message and KEM ciphertext (from a previous encryption)
2. Click the **"Decrypt"** button
3. The application will:
   - Use your secret key to recover the shared secret from the KEM ciphertext
   - Derive the same AES-256 key
   - Decrypt the message and remove padding
4. The original plaintext is displayed as "Decrypted Message"

---

## Technical Details

### Kyber512 Algorithm Details

**Kyber512** is a lattice-based key encapsulation mechanism with the following characteristics:

- **Security Level**: 128-bit equivalent security against quantum computers
- **Public Key Size**: 352 bytes
- **Secret Key Size**: 1632 bytes
- **Ciphertext Size**: 320 bytes
- **Shared Secret Size**: 32 bytes
- **Basis**: Module-LWE (Learning With Errors) problem

### AES-256-CBC Encryption

- **Algorithm**: AES (Advanced Encryption Standard) with 256-bit key
- **Mode**: CBC (Cipher Block Chaining)
- **Block Size**: 128 bits (16 bytes)
- **Key Size**: 256 bits (32 bytes)
- **Padding**: PKCS7 (handled automatically)
- **IV Generation**: Cryptographically random 16-byte IV for each encryption

### Session Management

- **Type**: Filesystem-based (default) or Redis (production)
- **Expiration**: 15 minutes of inactivity
- **Storage**: Base64-encoded keys stored in server-side sessions
- **Security**: Protected by Flask's `SECRET_KEY`

---

## Configuration Options

Edit `app.py` to modify the following settings:

### Redis for Session Storage (Production)
Uncomment these lines in `app.py` to use Redis instead of filesystem:
```python
# app.config['SESSION_TYPE'] = 'redis'
# app.config['SESSION_REDIS'] = Redis(host='redis', port=6379)
```

### Session Timeout
Modify the session lifetime:
```python
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
```

### HTTPS Enforcement
For production deployment with HTTPS:
```python
Talisman(app, force_https=True)
```

---

## Security Considerations

1. **Key Storage**: Keys are stored in server-side sessions. Never store keys in cookies or client-side storage.

2. **Session Expiration**: Keys automatically expire after 15 minutes. Generate new keys for each session to maintain security.

3. **Environment Variables**: Keep your `SECRET_KEY` in the `.env` file and never commit it to version control.

4. **HTTPS**: Always use HTTPS in production to protect keys in transit.

5. **Quantum-Resistance**: While Kyber512 is quantum-resistant, it's still a relatively new algorithm. Stay updated with NIST recommendations.

6. **Randomness**: All encryption operations use cryptographically secure random number generation (`os.urandom`).

---

## Logging & Error Handling

The application includes comprehensive logging:

- **Success Messages**: Logged when key generation, encryption, and decryption complete successfully
- **Warning Messages**: Logged when operations are attempted without proper setup
- **Error Messages**: Logged when cryptographic operations fail
- **Log Level**: Set to INFO; viewable in console output

All user-facing errors are handled gracefully with user-friendly flash messages.

---

## Deployment

### PythonAnywhere Deployment

The application was originally deployed on **PythonAnywhere.com**:
- Previous URL: `https://zaraar.pythonanywhere.com/` (currently not active)

For deploying on PythonAnywhere:
1. Clone repository to PythonAnywhere
2. Create a virtual environment and install requirements
3. Configure WSGI file to point to the Flask app
4. Set environment variables in PythonAnywhere's web app config
5. Enable HTTPS in the web app settings

### Docker Deployment

Use the provided `Dockerfile` and `docker-compose.yaml` for containerized deployment:

```bash
docker-compose up -d
```

This will:
- Build the Flask application container
- Expose port 5000
- Mount volumes for code updates
- Ready for scaling and orchestration

### Production Recommendations

1. Use a production WSGI server (Gunicorn, uWSGI)
2. Enable HTTPS with SSL certificates
3. Use Redis for session storage
4. Implement rate limiting
5. Monitor logs and errors
6. Use environment variables for sensitive configuration
7. Consider behind a reverse proxy (Nginx)

---

## Development Notes

### File Descriptions

| File | Purpose |
|------|---------|
| `app.py` | Core Flask application with all cryptographic logic |
| `templates/index.html` | HTML interface for user interaction |
| `static/style.css` | Application styling |
| `requirements.txt` | Python package dependencies |
| `Dockerfile` | Container image specification |
| `docker-compose.yaml` | Multi-container orchestration |

### Common Issues & Solutions

**Issue**: "Key pair not generated" error
- **Solution**: Click "Generate Keys" first before encrypting

**Issue**: Decryption fails with padding error
- **Solution**: Ensure you're using the correct encrypted message and KEM ciphertext pair

**Issue**: Keys expire during use
- **Solution**: Keys expire after 15 minutes. Generate new keys if needed

**Issue**: `ModuleNotFoundError` when running
- **Solution**: Ensure virtual environment is activated and dependencies are installed (`pip install -r requirements.txt`)

---

## Educational Value

This project demonstrates:
- **Post-Quantum Cryptography**: Understanding quantum-resistant algorithms
- **Key Encapsulation Mechanisms (KEM)**: How modern key exchange works
- **Hybrid Encryption**: Combining asymmetric and symmetric encryption
- **Web Security**: Implementing cryptography in web applications
- **Session Management**: Secure server-side state management
- **Best Practices**: Error handling, logging, and security headers

---

## Future Enhancements

Potential improvements for this project:

1. Support for multiple users with database storage
2. Key backup and recovery mechanisms
3. File encryption/decryption capabilities
4. Digital signatures using Dilithium
5. Key distribution protocols
6. Performance benchmarking tools
7. Integration with hardware security modules

---

## References

- **NIST Post-Quantum Cryptography**: https://csrc.nist.gov/Projects/post-quantum-cryptography/
- **Kyber Algorithm Specification**: https://pq-crystals.org/kyber/
- **Flask Documentation**: https://flask.palletsprojects.com/
- **AES/CBC Mode**: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC

---

## License

This project is provided for educational and demonstrative purposes.

---

## Contact & Support

For questions or issues regarding this project, please refer to the application logs for detailed error information.

---

**Last Updated**: Feb 2025

**Status**: No Active Development
