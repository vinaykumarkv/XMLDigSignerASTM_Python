import xmlsec
from lxml import etree
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
import base64


def generate_keys():
    private_key = dsa.generate_private_key(key_size=1024)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem, public_key_pem


def load_private_key(private_key_pem):
    key = xmlsec.Key.from_memory(private_key_pem, xmlsec.constants.KeyDataFormatPem, None)
    return key


def sign_xml(xml_file, signed_file, key, public_key_pem):
    doc = etree.parse(xml_file)
    sign_ctx = xmlsec.SignatureContext()
    sign_ctx.key = key

    # Create the Signature node with the specified CanonicalizationMethod and SignatureMethod
    signature_node = xmlsec.template.create(
        doc,
        xmlsec.constants.TransformInclC14N,  # CanonicalizationMethod: http://www.w3.org/TR/2001/REC-xml-c14n-20010315
        xmlsec.constants.TransformDsaSha1  # SignatureMethod: http://www.w3.org/2000/09/xmldsig#dsa-sha1
    )
    doc.getroot().append(signature_node)

    # Add the Reference node with the specified DigestMethod
    ref = xmlsec.template.add_reference(
        signature_node,
        xmlsec.constants.TransformSha256,  # DigestMethod: http://www.w3.org/2001/04/xmlenc#sha256
        uri=""
    )
    xmlsec.template.add_transform(ref, xmlsec.constants.TransformEnveloped)

    key_info = xmlsec.template.ensure_key_info(signature_node)
    key_value = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}KeyValue")
    dsa_key_value = etree.SubElement(key_value, "{http://www.w3.org/2000/09/xmldsig#}DSAKeyValue")
    p = etree.SubElement(dsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}P")
    q = etree.SubElement(dsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}Q")
    g = etree.SubElement(dsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}G")
    y = etree.SubElement(dsa_key_value, "{http://www.w3.org/2000/09/xmldsig#}Y")

    public_key = serialization.load_pem_public_key(public_key_pem)
    numbers = public_key.public_numbers()
    p.text = base64.b64encode(numbers.parameter_numbers.p.to_bytes((numbers.parameter_numbers.p.bit_length() + 7) // 8,
                                                                   byteorder='big')).decode('utf-8')
    q.text = base64.b64encode(numbers.parameter_numbers.q.to_bytes((numbers.parameter_numbers.q.bit_length() + 7) // 8,
                                                                   byteorder='big')).decode('utf-8')
    g.text = base64.b64encode(numbers.parameter_numbers.g.to_bytes((numbers.parameter_numbers.g.bit_length() + 7) // 8,
                                                                   byteorder='big')).decode('utf-8')
    y.text = base64.b64encode(numbers.y.to_bytes((numbers.y.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')

    sign_ctx.sign(signature_node)

    with open(signed_file, 'wb') as f:
        f.write(etree.tostring(doc, pretty_print=True, xml_declaration=True, encoding='UTF-8'))


def is_xml_signed(xml_file):
    try:
        doc = etree.parse(xml_file)
        signature_node = xmlsec.tree.find_node(doc, xmlsec.constants.NodeSignature, xmlsec.constants.DSigNs)
        return signature_node is not None
    except Exception as e:
        raise ValueError(f"An error occurred while checking the signature: {e}")