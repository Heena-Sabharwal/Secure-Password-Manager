# Secure Password Manager

A desktop-based password manager built using **Python, Tkinter, SQLite, and Fernet encryption**. It provides a simple interface to securely store, manage, search, and retrieve login credentials locally.

The application uses a master password for access and encrypts sensitive information before storing it in the database.

## Features

- **Master Password Protection:** Access the application using a master password.
- **Encrypted Storage:** Website names, usernames, and passwords are encrypted before being stored in the database.
- **Add Credentials:** Save login details for different websites and applications.
- **View Credentials:** Retrieve and view saved login information.
- **Edit Credentials:** Update existing website, username, or password details.
- **Delete Credentials:** Remove saved login entries.
- **Search Functionality:** Quickly find credentials using website names or usernames.
- **Password Visibility Toggle:** Show or hide passwords using an eye icon.
- **Copy to Clipboard:** Copy saved passwords directly to the clipboard.
- **Favourites:** Mark frequently used login entries for easy identification.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Tkinter | Graphical user interface |
| SQLite | Local database for storing credentials |
| Cryptography (Fernet) | Encryption and decryption of sensitive data |
| PBKDF2HMAC | Deriving an encryption key from the master password |

## How It Works

1. **Master Password Setup:** During initial setup, the user creates a master password.
2. **Key Derivation:** PBKDF2HMAC with SHA-256 and a randomly generated salt derives a cryptographic key from the master password.
3. **Encryption:** Fernet uses the derived key to encrypt sensitive credential information.
4. **Database Storage:** Encrypted credentials are stored in a local SQLite database.
5. **Authentication:** On subsequent launches, the user must enter the master password to access the application.
6. **Decryption:** Once authenticated, the application decrypts the stored information when required.

## Installation and Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
```

### 2. Navigate to the Project Directory

```bash
cd "Secure Password Manager"
```

### 3. Install Dependencies

```bash
pip install cryptography
```

**Note:** Tkinter and SQLite are included with most standard Python installations.

### 4. Run the Application

```bash
python secure_password_manager.py
```

On the first launch, set up your master password. On subsequent launches, enter it to access your saved credentials.

## Project Structure

```text
Secure Password Manager/
│
├── secure_password_manager.py
├── passwords.db //Hidden for now
└── README.md
```

- `secure_password_manager.py`: Contains the application logic, GUI, database operations, and encryption functionality.
- `passwords.db`: Local SQLite database containing encrypted credential records. It is generated when the application initializes the database.

## Security Considerations

- Sensitive credential fields are encrypted before being stored in SQLite.
- A randomly generated salt is used during key derivation.
- PBKDF2HMAC increases the computational cost of deriving the encryption key from the master password.
- The master password should be strong and kept private.
- The database should be backed up securely. Losing the database or the master password may result in permanent loss of access to stored credentials.
- Passwords copied to the clipboard may remain accessible through the system clipboard until overwritten or cleared.

**Important:** This is an educational, local-first password management project. It is not a substitute for a professionally audited password manager.

## Future Improvements

- **Browser Integration:** Integrate with web browsers to detect login pages and help users access their saved credentials.
- **Password Generator:** Generate strong passwords with customizable length and character types.
- **Automatic Clipboard Clearing:** Clear copied passwords from the clipboard after a specified duration.
- **Password Strength Evaluation:** Assess password strength and identify weak credentials.
- **Secure Backup and Restore:** Support exporting and importing encrypted credential backups.
- **Improved User Interface:** Enhance the application's usability and accessibility.

## Author

Heena Sabharwal
