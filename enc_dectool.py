import tkinter as tk
from tkinter import filedialog, messagebox

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            result += chr((ord(char) - shift_base - shift) % 26 + shift_base)
            key_index += 1
        else:
            result += char
    return result

def encrypt():
    algorithm = algorithm_var.get()
    text = text_var.get()
    key = key_var.get()
    if algorithm == "Caesar Cipher":
        try:
            shift = int(key)
            encrypted_text = caesar_encrypt(text, shift)
        except ValueError:
            messagebox.showerror("Error", "Key must be an integer for Caesar Cipher")
            return
    elif algorithm == "Vigenère Cipher":
        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters for Vigenère Cipher")
            return
        encrypted_text = vigenere_encrypt(text, key)
    output_var.set(encrypted_text)

def decrypt():
    algorithm = algorithm_var.get()
    text = text_var.get()
    key = key_var.get()
    if algorithm == "Caesar Cipher":
        try:
            shift = int(key)
            decrypted_text = caesar_decrypt(text, shift)
        except ValueError:
            messagebox.showerror("Error", "Key must be an integer for Caesar Cipher")
            return
    elif algorithm == "Vigenère Cipher":
        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters for Vigenère Cipher")
            return
        decrypted_text = vigenere_decrypt(text, key)
    output_var.set(decrypted_text)

def save_message():
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file:
        with open(file, "w") as f:
            f.write(output_var.get())

def load_message():
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file:
        with open(file, "r") as f:
            text_var.set(f.read())

root = tk.Tk()
root.title("Encryption and Decryption Tool")
root.geometry("500x400")

algorithm_var = tk.StringVar(value="Caesar Cipher")
text_var = tk.StringVar()
key_var = tk.StringVar()
output_var = tk.StringVar()

tk.Label(root, text="Select Algorithm:").pack()
tk.OptionMenu(root, algorithm_var, "Caesar Cipher", "Vigenère Cipher").pack()
tk.Label(root, text="Text:").pack()
tk.Entry(root, textvariable=text_var, width=50).pack()
tk.Label(root, text="Key:").pack()
tk.Entry(root, textvariable=key_var, width=50).pack()
tk.Button(root, text="Encrypt", command=encrypt).pack(pady=5)
tk.Button(root, text="Decrypt", command=decrypt).pack(pady=5)
tk.Label(root, text="Output:").pack()
tk.Entry(root, textvariable=output_var, width=50, state="readonly").pack()
tk.Button(root, text="Save Output", command=save_message).pack(pady=5)
tk.Button(root, text="Load Message", command=load_message).pack(pady=5)

root.mainloop()
