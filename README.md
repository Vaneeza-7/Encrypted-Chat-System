# Secure Chat System with Registration, Login, and Encrypted Communication

## Introduction

This project implements a **Secure Chat System** that provides encrypted communication between clients and a server. It features user registration, login authentication, and secure messaging using **Diffie-Hellman key exchange**, **SHA-256 hashing**, and **AES encryption**.

The system ensures:
- Secure storage of user credentials.
- Confidentiality of messages.
- Robust authentication and encryption mechanisms.

## Features

1. **User Registration**
   - Users register with a unique username, email, and password.
   - Credentials are securely encrypted and stored.

2. **User Login**
   - Users authenticate with their credentials.
   - Credentials are validated securely using hashing and salting.

3. **Encrypted Messaging**
   - Communication between the client and server is encrypted using AES-128.

4. **Security Measures**
   - **SHA-256 hashing with salting** for password security.
   - **Diffie-Hellman key exchange** for secure session keys.

## Key Components

1. **Diffie-Hellman Key Exchange**
   - Securely generates and exchanges session keys.

2. **Password Security**
   - Passwords are hashed with **SHA-256** and unique salts for each user.

3. **AES Encryption**
   - AES-128 encryption in CBC mode is used for secure message communication.

4. **Credential Storage**
   - User credentials are securely stored in `creds.txt` as:
     ```
     Email,Username,SHA256_HashedPassword,Salt
     ```

## Prerequisites

- **C++ Compiler** (supporting C++17 or higher).
- OpenSSL (for cryptographic functions).


## How to Build and Run

### Steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/Vaneeza-7/Encrypted-Chat-System.git
   ```

2. Compile the server and client files separately:
   ```bash
   g++ -o server server/server.cpp -lssl -lcrypto
   g++ -o client client/client.cpp -lssl -lcrypto
   ```

3. Run the server and client in separate terminals:
   - Start the server:
     ```bash
     ./server
     ```
   - Start the client:
     ```bash
     ./client
     ```

## Testing

### Functional Tests
1. **Registration**
   - Verify successful registration with unique usernames.
   - Confirm passwords are securely hashed and salted.

2. **Login**
   - Test login with correct and incorrect credentials.

3. **Encrypted Chat**
   - Ensure all messages are encrypted during transmission.

### Security Tests
- Confirm that identical passwords result in different hashes due to salting.
- Use tools (e.g., Wireshark) to verify encryption of communication.

---

## License

This project is licensed under the [MIT License](LICENSE).
