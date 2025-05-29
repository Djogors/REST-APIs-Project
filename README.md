# REST-APIs-Project
This project demonstrates a distributed marketplace system where multiple computers (peers) are interconnected. Users can buy products, add items for sale, and securely connect with each other through a certificate-based registration system.

🛠️ Project Overview
A decentralized marketplace where each peer can act as both buyer and seller.

Communication is handled via RESTful APIs.

Security is ensured through certificate-based authentication.

🔐 Authentication & Security
Users must register through an admin to receive a digital certificate.

Each user generates a private and public key pair used for secure communication.

Users can manually connect to other peers using certificates for verification.

💡 Key Features
✅ Add and list products in the marketplace

🛒 Buy products from other users

🔑 Public/Private key generation per user

📜 Admin-issued certificates for secure peer connection

🌐 Peer-to-peer manual connection system

🧱 Technologies Used
REST APIs (e.g., using Flask, Express, or similar)

X.509 certificates for identity and trust

Custom key management (public/private)

JSON for data interchange


