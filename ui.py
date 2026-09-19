
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class App(tk.Tk):
    def __init__(self, version, check_for_updates_callback, update_callback):
        super().__init__()
        self.version = version
        self.check_for_updates_callback = check_for_updates_callback
        self.update_callback = update_callback

        self.title(f"EncryptorX {self.version}")
        self.geometry("800x600")
        self.configure(bg="#2E2E2E")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#2E2E2E")
        self.style.configure("TLabel", background="#2E2E2E", foreground="#FFFFFF", font=("Arial", 12))
        self.style.configure("TButton", background="#4A4A4A", foreground="#FFFFFF", font=("Arial", 12, "bold"), borderwidth=0)
        self.style.map("TButton", background=[("active", "#6E6E6E")])
        self.style.configure("TEntry", fieldbackground="#4A4A4A", foreground="#FFFFFF", insertbackground="#FFFFFF")

        self.create_widgets()
        self.check_for_updates()

    def create_widgets(self):
        # Using Notebook for Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # --- Tab 1: Custom Encryption ---
        self.encrypt_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.encrypt_tab, text=" EncryptorX ")

        # Input Section
        input_label = ttk.Label(self.encrypt_tab, text="Input Text / File Area:")
        input_label.pack(anchor="w")
        self.input_text = tk.Text(self.encrypt_tab, height=8, width=80, bg="#4A4A4A", fg="#FFFFFF", insertbackground="#FFFFFF", relief="flat")
        self.input_text.pack(expand=True, fill="both")

        # Output Section
        output_label = ttk.Label(self.encrypt_tab, text="Output:")
        output_label.pack(anchor="w", pady=(10, 0))
        self.output_text = tk.Text(self.encrypt_tab, height=8, width=80, bg="#4A4A4A", fg="#FFFFFF", insertbackground="#FFFFFF", relief="flat")
        self.output_text.pack(expand=True, fill="both")

        # Buttons for Encrypt/Decrypt
        button_frame = ttk.Frame(self.encrypt_tab)
        button_frame.pack(pady=10)

        self.encrypt_text_button = ttk.Button(button_frame, text="Encrypt Text", command=self.encrypt_text)
        self.encrypt_text_button.grid(row=0, column=0, padx=5)

        self.decrypt_text_button = ttk.Button(button_frame, text="Decrypt Text", command=self.decrypt_text)
        self.decrypt_text_button.grid(row=0, column=1, padx=5)

        self.encrypt_file_button = ttk.Button(button_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_button.grid(row=1, column=0, padx=5, pady=5)

        self.decrypt_file_button = ttk.Button(button_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_button.grid(row=1, column=1, padx=5, pady=5)

        # --- Tab 2: Base64 ---
        self.base64_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.base64_tab, text=" Base64 ")

        b64_input_label = ttk.Label(self.base64_tab, text="Input Text for Base64:")
        b64_input_label.pack(anchor="w")
        self.b64_input_text = tk.Text(self.base64_tab, height=8, width=80, bg="#4A4A4A", fg="#FFFFFF", insertbackground="#FFFFFF", relief="flat")
        self.b64_input_text.pack(expand=True, fill="both")

        b64_output_label = ttk.Label(self.base64_tab, text="Base64 Output:")
        b64_output_label.pack(anchor="w", pady=(10, 0))
        self.b64_output_text = tk.Text(self.base64_tab, height=8, width=80, bg="#4A4A4A", fg="#FFFFFF", insertbackground="#FFFFFF", relief="flat")
        self.b64_output_text.pack(expand=True, fill="both")

        b64_button_frame = ttk.Frame(self.base64_tab)
        b64_button_frame.pack(pady=10)

        self.b64_encode_button = ttk.Button(b64_button_frame, text="Base64 Encode", command=self.base64_encode)
        self.b64_encode_button.grid(row=0, column=0, padx=5)

        self.b64_decode_button = ttk.Button(b64_button_frame, text="Base64 Decode", command=self.base64_decode)
        self.b64_decode_button.grid(row=0, column=1, padx=5)

    def check_for_updates(self):
        update_info = self.check_for_updates_callback()
        if update_info:
            latest_version, download_url = update_info
            if messagebox.askyesno("Update Available", f"A new version ({latest_version}) is available. Would you like to update?"):
                self.update_callback(download_url, ui_mode=True)

    def set_callbacks(self, encrypt_text_callback, decrypt_text_callback, encrypt_file_callback, decrypt_file_callback, b64_encode_callback=None, b64_decode_callback=None):
        self.encrypt_text_callback = encrypt_text_callback
        self.decrypt_text_callback = decrypt_text_callback
        self.encrypt_file_callback = encrypt_file_callback
        self.decrypt_file_callback = decrypt_file_callback
        self.b64_encode_callback = b64_encode_callback
        self.b64_decode_callback = b64_decode_callback

    def encrypt_text(self):
        input_text = self.input_text.get("1.0", tk.END).strip()
        if input_text:
            try:
                encrypted_text = self.encrypt_text_callback(input_text)
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, encrypted_text)
            except Exception as e:
                messagebox.showerror("Encryption Error", f"An error occurred: {e}")

    def decrypt_text(self):
        input_text = self.input_text.get("1.0", tk.END).strip()
        if input_text:
            try:
                decrypted_text = self.decrypt_text_callback(input_text)
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, decrypted_text)
            except ValueError as e:
                messagebox.showerror("Decryption Error", str(e))

    def base64_encode(self):
        input_text = self.b64_input_text.get("1.0", tk.END).strip()
        if input_text and self.b64_encode_callback:
            try:
                encoded_text = self.b64_encode_callback(input_text)
                self.b64_output_text.delete("1.0", tk.END)
                self.b64_output_text.insert(tk.END, encoded_text)
            except Exception as e:
                messagebox.showerror("Base64 Error", str(e))

    def base64_decode(self):
        input_text = self.b64_input_text.get("1.0", tk.END).strip()
        if input_text and self.b64_decode_callback:
            try:
                decoded_text = self.b64_decode_callback(input_text)
                self.b64_output_text.delete("1.0", tk.END)
                self.b64_output_text.insert(tk.END, decoded_text)
            except Exception as e:
                messagebox.showerror("Base64 Error", str(e))

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                encrypted_file_path = self.encrypt_file_callback(file_path)
                messagebox.showinfo("EncryptorX", f"File encrypted successfully:\n{encrypted_file_path}")
            except Exception as e:
                messagebox.showerror("Encryption Error", f"Could not encrypt the file:\n{e}")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select .enc file", filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            try:
                decrypted_file_path = self.decrypt_file_callback(file_path)
                messagebox.showinfo("EncryptorX", f"File decrypted successfully:\n{decrypted_file_path}")
            except ValueError as e:
                messagebox.showerror("Decryption Error", str(e))

if __name__ == '__main__':
    # This is for testing the UI in isolation
    def fake_check_for_updates():
        print("Checking for updates...")
        return None

    def fake_update(url, ui_mode):
        print(f"Updating from {url}...")

    def fake_encrypt_text(text):
        return text[::-1]

    def fake_decrypt_text(text):
        return text[::-1]
    
    def fake_encrypt_file(path):
        return path + ".enc"

    def fake_decrypt_file(path):
        return path[:-4]

    app = App("v1.2.2", fake_check_for_updates, fake_update)
    app.set_callbacks(fake_encrypt_text, fake_decrypt_text, fake_encrypt_file, fake_decrypt_file)
    app.mainloop()
