# PQC Flask App - Kyber512 + AES

## Overview
A Flask web app demonstrating Post-Quantum Cryptography using Kyber512 (KEM) + AES-256 for message encryption/decryption.

## Technologies
- Python 3
- Flask
- pqc (Kyber512)
- pycryptodome (AES)
- Bootstrap CSS (optional)

## Setup
1. Clone repository
2. Create a virtual environment
3. Install requirements: `pip install -r requirements.txt`
4. Copy `.env.example` → `.env` and set your `SECRET_KEY`
5. Run: `python app.py`

## Features
- PQC Keypair generation
- Shared secret encapsulation (Kyber512)
- AES-256 encryption/decryption of messages
- Secure headers using Flask-Talisman

## Deployment 
- PythonAnywhere.com is used for Deployment
- Link : zaraar.pythonanywhere.com

---
