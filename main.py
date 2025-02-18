import tkinter as tk
from tkinter import filedialog, messagebox
from signer import generate_keys, load_private_key, sign_xml, is_xml_signed
from verifier import extract_public_key, load_public_key, verify_xml


def sign_button_action():
    xml_file = filedialog.askopenfilename(filetypes=[("XML files", "*.xml")])
    if not xml_file:
        return

    if is_xml_signed(xml_file):
        messagebox.showinfo("Information", "The XML document is already signed.")
        return

    signed_file = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML files", "*.xml")])
    if not signed_file:
        return

    try:
        private_key_pem, public_key_pem = generate_keys()
        key = load_private_key(private_key_pem)
        sign_xml(xml_file, signed_file, key, public_key_pem)
        messagebox.showinfo("Success", f"Signed XML document saved to: {signed_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


def verify_button_action():
    signed_file = filedialog.askopenfilename(filetypes=[("XML files", "*.xml")])
    if not signed_file:
        return

    try:
        public_key_pem = extract_public_key(signed_file)
        key = load_public_key(public_key_pem)
        if verify_xml(signed_file, key):
            messagebox.showinfo("Success", "Signature verification succeeded.")
    except Exception as e:
        messagebox.showerror("Error", f"Signature verification failed: {e}")


def main():
    root = tk.Tk()
    root.title("XML Signature App")

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(padx=10, pady=10)

    sign_button = tk.Button(frame, text="Sign XML Document", command=sign_button_action)
    sign_button.grid(row=0, column=0, padx=10, pady=10)

    verify_button = tk.Button(frame, text="Verify XML Document", command=verify_button_action)
    verify_button.grid(row=0, column=1, padx=10, pady=10)

    root.mainloop()


if __name__ == '__main__':
    main()