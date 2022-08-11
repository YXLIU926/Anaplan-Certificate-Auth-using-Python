from base64 import b64encode
import os
import requests
from OpenSSL import crypto
import random
import string
"""
docstring
"""

def get_auth_token(certfile,keyfile):
    url = 'https://auth.anaplan.com/token/authenticate'
    st_cert=open(certfile, 'rt').read()
    cert=crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)

    st_key=open(keyfile, 'rt').read()
    key=crypto.load_privatekey(crypto.FILETYPE_PEM, st_key)

    pem = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
    random_str = os.urandom(100)
    signed_str = crypto.sign(key, random_str, "sha512")

    auth_headers = "'authorization': CACertificate %s" % (st_cert.replace("\n", "").replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", ""))
    authenHeader = "CACertificate " + st_cert.replace("\n", "").replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")

    auth_headers = {'Authorization': authenHeader,
        "Content-Type": "application/json"
    }

    encodedstr = "'"+b64encode(random_str).decode("utf-8")+"'"
    signedstr = "'"+b64encode(signed_str).decode("utf-8")+"'"
    auth_data = "{" + "'encodedData': %s" % encodedstr + "," + "'encodedSignedData':%s" % signedstr + "}"
    auth_data = eval(auth_data) # convert the body part into json format

    init_auth_token = requests.post(url, headers = auth_headers, json = auth_data).json()
    auth_token = init_auth_token.get('tokenInfo').get('tokenValue')
    auth_headers['Authorization'] = 'AnaplanAuthToken ' + auth_token

    get_ws_url = 'https://api.anaplan.com/2/0/workspaces/'
    get_ws = requests.get(get_ws_url, headers = auth_headers)
    with open('workspaces.json','wb') as f:
        f.write(get_ws.text.encode('utf-8'))

certfile = "/Users/yunxin.liu/Desktop/CACertificate/pubCert.pem"
keyfile = "/Users/yunxin.liu/Desktop/CACertificate/yunxin_liu.key"

get_auth_token(certfile,keyfile)
