# XML Signer and Verifier

This repository contains three main components for XML signing and verification:
1. `signer.py`
2. `verifier.py`
3. `main.py`

## Dependencies

This project requires the following Python libraries:

- `lxml`
- `xmlsec`
- `cryptography`
- `tkinter` (usually included with Python)

## Installation

To install the required libraries, you can use `pip`. Open a terminal and run the following command:

bash
pip install lxml xmlsec cryptography

## Components

### 1. `signer.py`

**Purpose:**  
The `signer.py` module provides functions to generate DSA keys, sign XML documents, and check if an XML is already signed.

**Functions:**
- `generate_keys()`: Generates a pair of DSA keys (private and public) in PEM format.
- `load_private_key(private_key_pem)`: Loads a private key from PEM format.
- `is_xml_signed(doc)`: Checks if the given XML document contains a signature.
- `sign_xml(xml_file, signed_file, key, public_key_pem)`: Signs the given XML file using the provided private key and public key PEM, and saves the signed XML.

### 2. `verifier.py`

**Purpose:**  
The `verifier.py` module provides functions to extract the public key from a signed XML, load a public key, and verify the signature of an XML document.

**Functions:**
- `extract_public_key(signed_file)`: Extracts the public key from the signed XML file in PEM format.
- `load_public_key(public_key_pem)`: Loads a public key from PEM format.
- `verify_xml(signed_file, key)`: Verifies the signature of the signed XML file using the provided public key.

### 3. `main.py`

**Purpose:**  
The `main.py` module contains the main application logic, including a Tkinter GUI for user interaction. It allows users to sign and verify XML documents through a graphical interface.

**Classes:**
- `XMLSignerVerifierApp`: A Tkinter application class that provides buttons and text areas for signing and verifying XML documents.

## Integration

### Integrating `signer.py`

To integrate the `signer.py` module into other systems:

1. **Import Functions:**
'''python
from signer import generate_keys, load_private_key, sign_xml, is_xml_signed

### Generate Keys:
'''python
private_key_pem, public_key_pem = generate_keys()
Load Private Key:
key = load_private_key(private_key_pem)

### Sign XML:
'''python
sign_xml(xml_file, signed_file, key, public_key_pem)
Check if XML is Signed:
doc = etree.parse(xml_file)
if is_xml_signed(doc):
    print("The XML document is already signed.")
Integrating verifier.py
To integrate the verifier.py module into other systems:

### Import Functions:
'''python
from verifier import extract_public_key, load_public_key, verify_xml
Extract Public Key:
public_key_pem = extract_public_key(signed_file)
Load Public Key:
key = load_public_key(public_key_pem)

###Verify XML:
'''python
if verify_xml(signed_file, key):
    print("Signature verification succeeded.")
else:
    print("Signature verification failed.")

### Integrating main.py
The main.py module can be run directly to launch the Tkinter GUI application. To integrate it with other systems, you can modify the GUI or use the classes and functions provided in signer.py and verifier.py within other applications.

### Run the Application:
python main.py

### Modify the GUI:
Open main.py in a text editor.
Customize the GUI elements and functionality as needed.

## Installation
To install the required libraries, use the following command:
'''python
pip install xmlsec lxml cryptography

### Usage
### Sign XML
- Click the "Sign XML" button.
- Select the XML file you want to sign.
- Choose a location to save the signed XML file.
- The application will generate keys, sign the XML, and save the signed document.

### Verify XML
- Click the "Verify XML" button.
- Select the signed XML file you want to verify.
- The application will extract the public key, load it, and verify the XML signature.


