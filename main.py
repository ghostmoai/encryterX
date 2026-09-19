"""
A Kivy-based application for text and file encryption/decryption.
"""
import os
from pathlib import Path
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.properties import ObjectProperty

import encryption_logic
from plyer import filechooser

class EncryptorXApp(App):
    """The main application class for EncryptorX."""
    input_text_widget = ObjectProperty(None)
    output_text_widget = ObjectProperty(None)

    def build(self):
        """Build the user interface."""
        self.title = "EncryptorX"

        encryption_logic.APP_DATA_DIR = Path(self.user_data_dir)
        encryption_logic.KEY_FILE = encryption_logic.APP_DATA_DIR / "key.key"
        encryption_logic.CLAVE = encryption_logic.get_or_generate_key()

        main_layout = BoxLayout(orientation="vertical", padding=10, spacing=10)

        main_layout.add_widget(Label(text="Input:", size_hint_y=None, height=30))
        self.input_text_widget = TextInput(
            hint_text="Enter text or select a file to encrypt/decrypt",
            multiline=True,
            size_hint_y=0.4,
            background_color=(0.2, 0.2, 0.2, 1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1)
        )
        main_layout.add_widget(self.input_text_widget)

        text_button_layout = BoxLayout(orientation="horizontal", size_hint_y=None, height=50, spacing=10)
        text_button_layout.add_widget(Button(text="Encrypt Text", on_press=self.encrypt_text))
        text_button_layout.add_widget(Button(text="Decrypt Text", on_press=self.decrypt_text))
        main_layout.add_widget(text_button_layout)

        b64_button_layout = BoxLayout(orientation="horizontal", size_hint_y=None, height=50, spacing=10)
        b64_button_layout.add_widget(Button(text="Base64 Encode", on_press=self.base64_encode))
        b64_button_layout.add_widget(Button(text="Base64 Decode", on_press=self.base64_decode))
        main_layout.add_widget(b64_button_layout)

        main_layout.add_widget(Label(text="Output:", size_hint_y=None, height=30))
        self.output_text_widget = TextInput(
            hint_text="Encrypted/Decrypted output will appear here",
            multiline=True,
            readonly=True,
            size_hint_y=0.4,
            background_color=(0.2, 0.2, 0.2, 1),
            foreground_color=(1, 1, 1, 1)
        )
        main_layout.add_widget(self.output_text_widget)

        file_button_layout = BoxLayout(orientation="horizontal", size_hint_y=None, height=50, spacing=10)
        file_button_layout.add_widget(Button(text="Encrypt File", on_press=self.select_file_to_encrypt))
        file_button_layout.add_widget(Button(text="Decrypt File", on_press=self.select_file_to_decrypt))
        main_layout.add_widget(file_button_layout)

        return main_layout

    def show_popup(self, title, message):
        """Display a popup window."""
        popup = Popup(title=title, content=Label(text=message), size_hint=(0.9, 0.3))
        popup.open()

    def encrypt_text(self, _instance):
        """Encrypt the text from the input widget."""
        input_text = self.input_text_widget.text.strip()
        if input_text:
            try:
                encrypted_text = encryption_logic.encrypt_text(input_text)
                self.output_text_widget.text = encrypted_text
            except ValueError as e:
                self.show_popup("Encryption Error", f"An error occurred: {e}")
        else:
            self.show_popup("Input Required", "Please enter text to encrypt.")

    def decrypt_text(self, _instance):
        """Decrypt the text from the input widget."""
        input_text = self.input_text_widget.text.strip()
        if input_text:
            try:
                decrypted_text = encryption_logic.decrypt_text(input_text)
                self.output_text_widget.text = decrypted_text
            except ValueError as e:
                self.show_popup("Decryption Error", str(e))
        else:
            self.show_popup("Input Required", "Please enter text to decrypt.")

    def base64_encode(self, _instance):
        """Encode the text to Base64."""
        input_text = self.input_text_widget.text.strip()
        if input_text:
            try:
                encoded_text = encryption_logic.base64_encode(input_text)
                self.output_text_widget.text = encoded_text
            except Exception as e:
                self.show_popup("Base64 Error", str(e))
        else:
            self.show_popup("Input Required", "Please enter text to encode.")

    def base64_decode(self, _instance):
        """Decode the text from Base64."""
        input_text = self.input_text_widget.text.strip()
        if input_text:
            try:
                decoded_text = encryption_logic.base64_decode(input_text)
                self.output_text_widget.text = decoded_text
            except Exception as e:
                self.show_popup("Base64 Error", f"Invalid Base64 string:\n{e}")
        else:
            self.show_popup("Input Required", "Please enter text to decode.")

    # --- File Encryption Flow ---
    def select_file_to_encrypt(self, _instance):
        """Step 1: Open a file to be encrypted."""
        filechooser.open_file(on_selection=self._process_file_to_encrypt)

    def _process_file_to_encrypt(self, selection):
        """Step 2: Read the selected file and get encrypted data."""
        if not selection:
            return
        
        file_path = selection[0]
        try:
            encrypted_data = encryption_logic.encrypt_file(file_path)
            # Add .enc to the original filename as a suggestion
            suggested_filename = os.path.basename(file_path) + ".enc"
            filechooser.save_file(
                on_selection=lambda p: self._save_file(p, encrypted_data),
                path=suggested_filename
            )
        except (IOError, ValueError) as e:
            self.show_popup("Encryption Error", f"Could not encrypt the file:\n{e}")

    # --- File Decryption Flow ---
    def select_file_to_decrypt(self, _instance):
        """Step 1: Open a file to be decrypted."""
        filechooser.open_file(on_selection=self._process_file_to_decrypt)

    def _process_file_to_decrypt(self, selection):
        """Step 2: Read the selected file and get decrypted data."""
        if not selection:
            return

        file_path = selection[0]
        try:
            decrypted_data = encryption_logic.decrypt_file(file_path)
            # Suggest a decrypted filename, removing .enc if present
            base_filename = os.path.basename(file_path)
            if base_filename.lower().endswith('.enc'):
                suggested_filename = base_filename[:-4]
            else:
                suggested_filename = f"{base_filename}.dec"

            filechooser.save_file(
                on_selection=lambda p: self._save_file(p, decrypted_data),
                path=suggested_filename
            )
        except ValueError as e:
            self.show_popup("Decryption Error", str(e))

    # --- Common File Saving Logic ---
    def _save_file(self, selection, data_to_save):
        """Step 3: Save the processed data (encrypted/decrypted) to the chosen path."""
        if not selection:
            self.show_popup("Save Cancelled", "File saving was cancelled.")
            return

        save_path = selection[0]
        try:
            with open(save_path, "wb") as f:
                f.write(data_to_save)
            self.show_popup("Success", f"File saved successfully at:\n{save_path}")
        except IOError as e:
            self.show_popup("Save Error", f"Could not save the file:\n{e}")

if __name__ == '__main__':
    EncryptorXApp().run()
