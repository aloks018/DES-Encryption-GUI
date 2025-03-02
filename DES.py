import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Function to encrypt data using DES
def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# Function to decrypt data using DES
def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES.block_size)
    return plaintext.decode()

# Function to handle encryption
def encrypt():
    key = key_entry.get()
    plaintext = plaintext_entry.get()

    if len(key) != 8:
        messagebox.showerror("Error", "Key must be 8 bytes long.")
        return

    try:
        key_bytes = key.encode()
        ciphertext = des_encrypt(key_bytes, plaintext)
        ciphertext_hex = ciphertext.hex()
        ciphertext_display.set(ciphertext_hex)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to handle decryption
def decrypt():
    key = key_entry.get()
    ciphertext_hex = ciphertext_entry.get()

    if len(key) != 8:
        messagebox.showerror("Error", "Key must be 8 bytes long.")
        return

    try:
        key_bytes = key.encode()
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        decrypted_plaintext = des_decrypt(key_bytes, ciphertext_bytes)
        decrypted_plaintext_display.set(decrypted_plaintext)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create the main window
root = tk.Tk()
root.title("DES Encryption/Decryption")
root.geometry("400x400")
root.configure(bg="#2c3e50")  # Dark blue background

# Styling options
label_style = {"bg": "#2c3e50", "fg": "#ecf0f1", "font": ("Arial", 12, "bold")}
entry_style = {"width": 30, "font": ("Arial", 12)}
button_style = {"bg": "#e74c3c", "fg": "white", "font": ("Arial", 12, "bold"), "padx": 10, "pady": 5}

# Key entry
key_label = tk.Label(root, text="Key (8 bytes):", **label_style)
key_label.pack(pady=5)
key_entry = tk.Entry(root, **entry_style)
key_entry.pack(pady=5)

# Plaintext entry
plaintext_label = tk.Label(root, text="Plaintext:", **label_style)
plaintext_label.pack(pady=5)
plaintext_entry = tk.Entry(root, **entry_style)
plaintext_entry.pack(pady=5)

# Encrypt button
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt, **button_style)
encrypt_button.pack(pady=5)

# Ciphertext display
ciphertext_label = tk.Label(root, text="Ciphertext (hex):", **label_style)
ciphertext_label.pack(pady=5)
ciphertext_display = tk.StringVar()
ciphertext_entry = tk.Entry(root, textvariable=ciphertext_display, **entry_style)
ciphertext_entry.pack(pady=5)

# Decrypt button
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt, **button_style)
decrypt_button.pack(pady=5)

# Decrypted plaintext display
decrypted_plaintext_label = tk.Label(root, text="Decrypted Plaintext:", **label_style)
decrypted_plaintext_label.pack(pady=5)
decrypted_plaintext_display = tk.StringVar()
decrypted_plaintext_entry = tk.Entry(root, textvariable=decrypted_plaintext_display, **entry_style)
decrypted_plaintext_entry.pack(pady=5)

# Run the application
root.mainloop()
