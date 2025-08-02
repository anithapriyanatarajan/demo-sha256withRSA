# Cryptography Education App: SHA256 & RSA Digital Signatures

## Overview
This educational Java application demonstrates the use of SHA256 hashing and RSA digital signatures, explaining why they are important for cybersecurity and why they are not quantum-safe.

## Educational Goals
- Understand why SHA256 hashing is needed
- Learn how digital signatures work with RSA
- See sender-receiver interaction in cryptographic communication
- Understand the quantum threat to current cryptography

## Features
1. **SHA256 Education**: Learn about hash functions and see the avalanche effect
2. **Digital Signature Demo**: See how RSA signatures provide authentication and integrity
3. **Sender-Receiver Simulation**: Interactive demonstration of secure communication
4. **Quantum Threat Explanation**: Understand why current crypto is vulnerable to quantum computers

## How to Run

### Prerequisites
- Java 8 or higher
- No external dependencies required (uses built-in Java cryptography)

### Compilation
```bash
javac CryptoEducationApp.java
```

### Execution
```bash
java CryptoEducationApp
```

## What You'll Learn

### SHA256 Hashing
- Why we need cryptographic hash functions
- Properties: deterministic, irreversible, avalanche effect
- Uses: data integrity, digital signatures, password storage

### RSA Digital Signatures
- How public-key cryptography enables digital signatures
- Authentication, integrity, and non-repudiation
- Why we hash before signing (efficiency and size limitations)

### Cryptographic Communication
- How sender and receiver interact securely
- Role of public and private keys
- Tamper detection capabilities

### Quantum Threat
- Why Shor's algorithm breaks RSA
- How Grover's algorithm weakens SHA256
- Introduction to post-quantum cryptography

## Interactive Features
The application provides an interactive menu where you can:
- Enter your own messages to hash and sign
- See real-time demonstrations of cryptographic operations
- Simulate secure communication between Alice and Bob
- Understand theoretical concepts through practical examples

## Educational Value
This application is designed for:
- Computer science students learning cryptography
- Security professionals understanding digital signatures
- Anyone interested in cybersecurity fundamentals
- Preparation for post-quantum cryptography transition

## Security Note
This is an educational demonstration. In production systems:
- Use established cryptographic libraries
- Implement proper key management
- Consider post-quantum cryptography for future-proofing
- Follow security best practices for key generation and storage

## Quantum-Safe Future
As quantum computers develop, we'll need to transition to:
- Post-quantum signature algorithms (e.g., CRYSTALS-Dilithium, FALCON)
- Quantum-resistant hash functions (e.g., SHA-3, BLAKE3)
- Crypto-agile systems that can easily update algorithms

Learn more about post-quantum cryptography: https://csrc.nist.gov/projects/post-quantum-cryptography
