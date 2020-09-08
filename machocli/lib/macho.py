from io import BytesIO
import struct
from asn1crypto.cms import ContentInfo
from asn1crypto.x509 import DirectoryString

CODE_INDEX = {
    0: 'CodeDirectorySlot',
    1: 'InfoSlot',
    2: 'RequirementsSlot',
    3: 'ResourceDirSlot',
    4: 'ApplicationSlot',
    5: 'EntitlementSlot',
    0x10000: 'SignatureSlot'
}

def read_int(b):
    return struct.unpack('>I', b.read(4))[0]


def extract_certificates(binary, data):
    """
    Extract and parse certificates from the file
    Largely inspired from macholibre
    """
    header = b"\xfa\xde\x0c\x05"
    cdata = None
    res = {}
    for c in binary.commands:
        if c.command.name == "CODE_SIGNATURE":
            cdata = data[c.data_offset:c.data_offset+c.data_size]
    if not cdata:
        return {}
    if not cdata.startswith(b'\xfa\xde\x0c\xc0'):
        print("Invalid Code signature header, weird")
        return {}
    b = BytesIO(cdata)
    _ = b.read(4) # Magic number
    size = read_int(b)
    count = read_int(b)

    for _ in range(count):
        index_type = read_int(b)
        if index_type not in CODE_INDEX:
            print("Unknown code signature index")
            b.read(4)
            continue
        index_offset = read_int(b)
        if index_type == 0x10000:
            # Certificates
            bb = BytesIO(cdata[index_offset:])
            if bb.read(4) != b"\xfa\xde\x0b\x01":
                print("Unknown magic type for certificates")
                continue
            size = read_int(bb)
            signed_data = ContentInfo.load(bb.read(size))['content']
            res['certs'] = []
            for cert in signed_data['certificates']:
                cert = cert.chosen
                subject = {}
                for rdn in cert.subject.chosen:
                    name = rdn[0]['type'].human_friendly
                    value = rdn[0]['value']

                    if name == 'Country':
                        subject['country'] = str(value.chosen)
                    elif name == 'Organization':
                        subject['org'] = str(value.chosen)
                    elif name == 'Organizational Unit':
                        subject['org_unit'] = str(value.chosen)
                    elif name == 'Common Name':
                        subject['common_name'] = str(value.chosen)
                    else:
                        if isinstance(value, DirectoryString):
                            subject[name] = str(value.chosen)
                        else:
                            subject[name] = str(value.parsed)


                issuer = {}

                for rdn in cert.issuer.chosen:
                    name = rdn[0]['type'].human_friendly
                    value = rdn[0]['value']

                    if name == 'Country':
                        issuer['country'] = str(value.chosen)
                    elif name == 'Organization':
                        issuer['org'] = str(value.chosen)
                    elif name == 'Organizational Unit':
                        issuer['org_unit'] = str(value.chosen)
                    elif name == 'Common Name':
                        issuer['common_name'] = str(value.chosen)
                    else:
                        if isinstance(value, DirectoryString):
                            issuer[name] = str(value.chosen)
                        else:
                            issuer[name] = str(value.parsed)

                res['certs'].append({
                    'subject': subject,
                    'issuer': issuer,
                    'serial': cert.serial_number,
                    'is_ca': cert.ca
                })

    return res










