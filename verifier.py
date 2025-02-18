import xmlsec
from lxml import etree
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
import base64


def extract_public_key(signed_file):
    doc = etree.parse(signed_file)
    key_info_node = xmlsec.tree.find_node(doc, xmlsec.constants.NodeKeyInfo, xmlsec.constants.DSigNs)
    if key_info_node is None:
        raise ValueError("KeyInfo node not found")

    key_value_node = key_info_node.find("{http://www.w3.org/2000/09/xmldsig#}KeyValue")
    if key_value_node is None:
        raise ValueError("KeyValue node not found")

    dsa_key_value_node = key_value_node.find("{http://www.w3.org/2000/09/xmldsig#}DSAKeyValue")
    if dsa_key_value_node is None:
        raise ValueError("DSAKeyValue node not found")

    p_node = dsa_key_value_node.find("{http://www.w3.org/2000/09/xmldsig#}P")
    q_node = dsa_key_value_node.find("{http://www.w3.org/2000/09/xmldsig#}Q")
    g_node = dsa_key_value_node.find("{http://www.w3.org/2000/09/xmldsig#}G")
    y_node = dsa_key_value_node.find("{http://www.w3.org/2000/09/xmldsig#}Y")

    if p_node is None or q_node is None or g_node is None or y_node is None:
        raise ValueError("DSA parameters not found in DSAKeyValue")

    p = int.from_bytes(base64.b64decode(p_node.text), byteorder='big')
    q = int.from_bytes(base64.b64decode(q_node.text), byteorder='big')
    g = int.from_bytes(base64.b64decode(g_node.text), byteorder='big')
    y = int.from_bytes(base64.b64decode(y_node.text), byteorder='big')

    parameter_numbers = dsa.DSAParameterNumbers(p, q, g)
    public_numbers = dsa.DSAPublicNumbers(y, parameter_numbers)
    public_key = public_numbers.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_pem


def load_public_key(public_key_pem):
    key = xmlsec.Key.from_memory(public_key_pem, xmlsec.constants.KeyDataFormatPem, None)
    return key


def verify_xml(signed_file, key):
    doc = etree.parse(signed_file)
    signature_node = xmlsec.tree.find_node(doc, xmlsec.constants.NodeSignature, xmlsec.constants.DSigNs)
    if signature_node is None:
        raise ValueError("Signature node not found")

    verify_ctx = xmlsec.SignatureContext()
    verify_ctx.key = key
    verify_ctx.verify(signature_node)
    return True