# Flask Store API

A Flask web application that provides user registration with two-factor authentication (2FA) and product management functionalities.

## Description

This project is a RESTful API built using Flask. It allows users to sign up and log in using a secure password and 2FA mechanism. Once authenticated, users can perform CRUD (Create, Read, Update, Delete) operations on products. The project utilizes SQLAlchemy for database interactions, Flask-Bcrypt for password hashing, and Flask-JWT-Extended for token-based authentication.

## Features

- **User Registration & Authentication**
  - User signup with password hashing.
  - Login that prompts for a two-factor authentication (2FA) code.
  - JWT-based session management.
  
- **Two-Factor Authentication (2FA)**
  - Generate and verify time-based one-time passwords (TOTP) using PyOTP.
  - Generate QR codes for easy 2FA setup.

- **Product Management**
  - Create, read, update, and delete products.
  - Each product includes details like name, description, price, stock, and creation timestamp.

## Technologies Used

- [Flask](https://flask.palletsprojects.com/)
- [Flask SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/)
- [Flask-Bcrypt](https://flask-bcrypt.readthedocs.io/)
- [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/)
- [PyOTP](https://pyauth.github.io/pyotp/)
- [qrcode](https://pypi.org/project/qrcode/)
- SQLite (as the database)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your_username/flask-store-api.git
   cd flask-store-api
