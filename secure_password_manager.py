import base64
import os
import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "passwords.db")
CHECK_TEXT = b"secure-password-manager-v1-unlocked"
PBKDF2_ITERATIONS = 600_000


def derive_fernet(master_password, salt):
    """Derive the same Fernet key from the master password and saved salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))
    return Fernet(key)


def create_tables(connection):
    connection.execute(
        "CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value BLOB NOT NULL)"
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website BLOB NOT NULL,
            username BLOB NOT NULL,
            password BLOB NOT NULL
        )"""
    )
    connection.commit()


def unlock_vault(root, connection):
    salt_row = connection.execute(
        "SELECT value FROM settings WHERE name = 'salt'"
    ).fetchone()
    verifier_row = connection.execute(
        "SELECT value FROM settings WHERE name = 'verifier'"
    ).fetchone()

    if salt_row is None and verifier_row is None:
        master_password = simpledialog.askstring(
            "Create your vault",
            "Create a strong master password (12+ characters recommended).\n"
            "You will need it every time you open this vault.",
            show="*",
            parent=root,
        )
        if master_password is None:
            return None
        if len(master_password) < 12:
            messagebox.showerror(
                "Master password too short",
                "Please use at least 12 characters. A memorable passphrase is a good choice.",
                parent=root,
            )
            return None

        confirmation = simpledialog.askstring(
            "Confirm master password",
            "Enter the master password again:",
            show="*",
            parent=root,
        )
        if confirmation is None:
            return None
        if master_password != confirmation:
            messagebox.showerror("Passwords do not match", "Please run the app again and try once more.", parent=root)
            return None

        salt = os.urandom(16)
        fernet = derive_fernet(master_password, salt)
        verifier = fernet.encrypt(CHECK_TEXT)
        connection.execute("INSERT INTO settings (name, value) VALUES (?, ?)", ("salt", salt))
        connection.execute("INSERT INTO settings (name, value) VALUES (?, ?)", ("verifier", verifier))
        connection.commit()
        return fernet

    if salt_row is None or verifier_row is None:
        messagebox.showerror(
            "Vault metadata error",
            "The vault's security metadata is incomplete. Do not delete or edit passwords.db manually.",
            parent=root,
        )
        return None

    master_password = simpledialog.askstring(
        "Unlock your vault", "Enter your master password:", show="*", parent=root
    )
    if master_password is None:
        return None

    fernet = derive_fernet(master_password, bytes(salt_row[0]))
    try:
        if fernet.decrypt(bytes(verifier_row[0])) != CHECK_TEXT:
            raise InvalidToken
    except (InvalidToken, ValueError, TypeError):
        messagebox.showerror("Could not unlock", "Incorrect master password or damaged vault.", parent=root)
        return None
    return fernet


def run_app():
    root = tk.Tk()
    root.withdraw()
    connection = sqlite3.connect(DB_PATH)
    create_tables(connection)

    fernet = unlock_vault(root, connection)
    if fernet is None:
        connection.close()
        root.destroy()
        return

    root.title("Secure Password Manager")
    root.geometry("820x540")
    root.minsize(760, 500)
    root.configure(bg="#f3f5f9")
    root.deiconify()

    title = tk.Label(
        root,
        text="Secure Password Manager",
        font=("Segoe UI", 20, "bold"),
        bg="#f3f5f9",
        fg="#172554",
        pady=14,
    )
    title.pack(fill="x")
    subtitle = tk.Label(
        root,
        text="Your credentials are encrypted before they are saved locally.",
        font=("Segoe UI", 10),
        bg="#f3f5f9",
        fg="#475569",
    )
    subtitle.pack(fill="x", pady=(0, 12))

    main = tk.Frame(root, bg="#f3f5f9", padx=16, pady=8)
    main.pack(fill="both", expand=True)
    main.grid_columnconfigure(0, weight=0, minsize=300)
    main.grid_columnconfigure(1, weight=1)
    main.grid_rowconfigure(0, weight=1)

    form = tk.LabelFrame(
        main, text="Add a login", font=("Segoe UI", 11, "bold"),
        bg="white", fg="#172554", padx=14, pady=14
    )
    form.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
    saved = tk.LabelFrame(
        main, text="Saved logins", font=("Segoe UI", 11, "bold"),
        bg="white", fg="#172554", padx=12, pady=12
    )
    saved.grid(row=0, column=1, sticky="nsew")
    saved.grid_rowconfigure(0, weight=1)
    saved.grid_columnconfigure(0, weight=1)

    def make_label(text, row):
        tk.Label(form, text=text, font=("Segoe UI", 10), bg="white", fg="#334155").grid(
            row=row, column=0, sticky="w", pady=(10, 4)
        )

    make_label("Website / service", 0)
    website_entry = tk.Entry(form, font=("Segoe UI", 10), width=30)
    website_entry.grid(row=1, column=0, sticky="ew", ipady=5)

    make_label("Username / email", 2)
    username_entry = tk.Entry(form, font=("Segoe UI", 10), width=30)
    username_entry.grid(row=3, column=0, sticky="ew", ipady=5)

    make_label("Password", 4)
    password_entry = tk.Entry(form, font=("Segoe UI", 10), width=30, show="*")
    password_entry.grid(row=5, column=0, sticky="ew", ipady=5)
    form.grid_columnconfigure(0, weight=1)

    def refresh_entries():
        listbox.delete(0, tk.END)
        rows = connection.execute(
            "SELECT id, website, username FROM entries ORDER BY id DESC"
        ).fetchall()
        for entry_id, encrypted_website, encrypted_username in rows:
            try:
                website = fernet.decrypt(bytes(encrypted_website)).decode("utf-8")
                username = fernet.decrypt(bytes(encrypted_username)).decode("utf-8")
                listbox.insert(tk.END, f"{entry_id} | {website} | {username}")
            except (InvalidToken, UnicodeDecodeError, TypeError):
                listbox.insert(tk.END, f"{entry_id} | [Unable to decrypt entry]")

    def add_entry():
        website = website_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get()
        if not website or not username or not password:
            messagebox.showwarning("Missing information", "Fill in all three fields first.", parent=root)
            return
        encrypted_values = (
            fernet.encrypt(website.encode("utf-8")),
            fernet.encrypt(username.encode("utf-8")),
            fernet.encrypt(password.encode("utf-8")),
        )
        with connection:
            connection.execute(
                "INSERT INTO entries (website, username, password) VALUES (?, ?, ?)",
                encrypted_values,
            )
        website_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        refresh_entries()
        messagebox.showinfo("Saved", "The encrypted login was saved.", parent=root)

    def selected_id():
        selection = listbox.curselection()
        if not selection:
            messagebox.showwarning("Select a login", "Choose a saved login first.", parent=root)
            return None
        try:
            return int(listbox.get(selection[0]).split("|", 1)[0].strip())
        except ValueError:
            messagebox.showerror("Selection error", "That list item could not be read.", parent=root)
            return None

    def view_password():
        entry_id = selected_id()
        if entry_id is None:
            return
        row = connection.execute(
            "SELECT website, username, password FROM entries WHERE id = ?", (entry_id,)
        ).fetchone()
        if row is None:
            messagebox.showerror("Not found", "That login no longer exists.", parent=root)
            refresh_entries()
            return
        try:
            website = fernet.decrypt(bytes(row[0])).decode("utf-8")
            username = fernet.decrypt(bytes(row[1])).decode("utf-8")
            password = fernet.decrypt(bytes(row[2])).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, TypeError):
            messagebox.showerror("Decryption error", "This saved entry could not be decrypted.", parent=root)
            return
        messagebox.showinfo(
            f"Login for {website}",
            f"Website: {website}\nUsername: {username}\n\nPassword: {password}",
            parent=root,
        )

    def delete_entry():
        entry_id = selected_id()
        if entry_id is None:
            return
        if not messagebox.askyesno("Delete login", "Permanently delete the selected login?", parent=root):
            return
        with connection:
            connection.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        refresh_entries()

    add_button = tk.Button(
        form, text="Save encrypted login", command=add_entry,
        font=("Segoe UI", 10, "bold"), bg="#2563eb", fg="white",
        activebackground="#1d4ed8", activeforeground="white", relief="flat", pady=9,
    )
    add_button.grid(row=6, column=0, sticky="ew", pady=(20, 8))
    tk.Label(
        form, text="Tip: use a unique, strong master passphrase.",
        bg="white", fg="#64748b", wraplength=250, justify="left",
        font=("Segoe UI", 9),
    ).grid(row=7, column=0, sticky="w", pady=(10, 0))

    list_frame = tk.Frame(saved, bg="white")
    list_frame.grid(row=0, column=0, sticky="nsew")
    list_frame.grid_rowconfigure(0, weight=1)
    list_frame.grid_columnconfigure(0, weight=1)
    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.grid(row=0, column=1, sticky="ns")
    listbox = tk.Listbox(
        list_frame, font=("Consolas", 10), selectmode=tk.SINGLE,
        yscrollcommand=scrollbar.set, activestyle="dotbox", height=15,
        borderwidth=0, highlightthickness=1, highlightbackground="#cbd5e1",
    )
    listbox.grid(row=0, column=0, sticky="nsew")
    scrollbar.config(command=listbox.yview)

    buttons = tk.Frame(saved, bg="white")
    buttons.grid(row=1, column=0, sticky="ew", pady=(12, 0))
    buttons.grid_columnconfigure(0, weight=1)
    buttons.grid_columnconfigure(1, weight=1)
    tk.Button(
        buttons, text="View password", command=view_password,
        font=("Segoe UI", 10, "bold"), bg="#0f766e", fg="white",
        activebackground="#115e59", activeforeground="white", relief="flat", pady=8,
    ).grid(row=0, column=0, sticky="ew", padx=(0, 5))
    tk.Button(
        buttons, text="Delete selected", command=delete_entry,
        font=("Segoe UI", 10, "bold"), bg="#b91c1c", fg="white",
        activebackground="#991b1b", activeforeground="white", relief="flat", pady=8,
    ).grid(row=0, column=1, sticky="ew", padx=(5, 0))
    tk.Button(
        saved, text="Refresh list", command=refresh_entries,
        font=("Segoe UI", 9), bg="#e2e8f0", fg="#1e293b", relief="flat", pady=5,
    ).grid(row=2, column=0, sticky="e", pady=(8, 0))

    def close_app():
        connection.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close_app)
    refresh_entries()
    website_entry.focus_set()
    root.mainloop()


if __name__ == "__main__":
    run_app()
