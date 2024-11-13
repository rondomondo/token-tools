#!/usr/bin/env python3
"""
JWT Token Verification Tool

Provides methods to decode and verify JWT tokens using either PyJWT
or multiple PKCS1_v1_5 verification methods.
Includes caching for JWKS (key sets) and outputs in JSON
"""

import os
import time
import json
import hmac
import hashlib
import base64
import argparse
from pathlib import Path
import datetime
from typing import Dict, Optional, Tuple, Union, Any
from base64 import urlsafe_b64decode, urlsafe_b64encode, b64decode

import requests
import jwt
from OpenSSL import crypto
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5, pkcs1_15
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.asn1 import DerSequence

from Utils import sha256, plog

# Custom Types
JWKSType = Dict[str, Any]
TokenSegments = Tuple[Dict[str, Any], Dict[str, Any], bytes]


class CryptoError(Exception):
    """Base exception for failed crypto operations"""
    pass


class CertificateManager:
    """Handles our X.509 certificate operations"""

    def __init__(self, base_dir: str = "keys"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)

    def _pad_base64(self, data: str) -> str:
        """Add padding to base64 encoded string if needed"""
        padding = 4 - (len(data) % 4)
        return data + ("=" * padding) if padding != 4 else data

    def generate_rsa_keypair(
        self,
        name: str = 'certificate',
        bits: int = 2048,
        key_dir: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Generate RSA key pair and save to files

        Args:
            name: Base name for key files
            bits: Key size in bits
            key_dir: Directory to save keys (uses base_dir if None)

        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        key_dir = Path(key_dir) if key_dir else self.base_dir
        key_dir.mkdir(exist_ok=True)

        # Generate key pair
        key = RSA.generate(bits, Random.new().read)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Save keys
        priv_path = key_dir / f"{name}.pem"
        pub_path = key_dir / f"{name}.key.pub"

        priv_path.write_bytes(private_key)
        pub_path.write_bytes(public_key)

        plog(f"Generated RSA key pair: {priv_path}, {pub_path}")
        return str(priv_path), str(pub_path)

    def create_self_signed_cert(
        self,
        name: str = 'certificate.crt',
        key_size: int = 2048,
        days_valid: int = 7,
        cert_dir: Optional[str] = None
    ) -> Tuple[str, str, str]:
        """
        Create self-signed X.509 certificate

        Args:
            name: Certificate filename
            key_size: RSA key size in bits
            days_valid: Certificate validity in days
            cert_dir: Directory to save certificate

        Returns:
            Tuple of (cert_path, private_key_path, public_key_path)
        """
        cert_dir = Path(cert_dir) if cert_dir else self.base_dir
        cert_dir.mkdir(exist_ok=True)

        # Generate key pair
        key_pair = crypto.PKey()
        key_pair.generate_key(crypto.TYPE_RSA, key_size)

        # Create certificate
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(1000)

        # Set subject
        subj = cert.get_subject()
        subj.C = "AU"
        subj.ST = "NSW"
        subj.L = "Sydney"
        subj.O = "ABCDEF Org"
        subj.OU = "SRE"
        subj.CN = "abcdef.ai"

        # Set validity
        cert.set_notBefore(datetime.datetime.now().strftime("%Y%m%d%H%M%SZ").encode())
        cert.gmtime_adj_notAfter(days_valid * 24 * 60 * 60)

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key_pair)
        cert.sign(key_pair, 'sha256')

        # Save public/private key and cert files
        cert_path = cert_dir / name
        key_path = cert_dir / f"{name.rsplit('.', 1)[0]}.pem"
        pub_key_path = cert_dir / f"{name.rsplit('.', 1)[0]}.key.pub"

        cert_path.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        key_path.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))

        # Extract public key
        pub_key = RSA.import_key(crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair))
        pub_key_path.write_bytes(pub_key.publickey().export_key())

        plog(json.dumps({"msg": f"Created self-signed certificate: {cert_path}"}))
        return str(cert_path), str(key_path), str(pub_key_path)


class SignatureManager:
    """Handles digital signature operations using PKI"""

    def __init__(self, cert_manager: CertificateManager):
        self.cert_manager = cert_manager

    def extract_public_key(self, cert_path: str, cert_format: str = 'PEM') -> Tuple[bytes, RSA.RsaKey]:
        """
        Extract the public key from an X.509 certificate

        Args:
            cert_path: Path to certificate file
            cert_format: Certificate format ('PEM' or 'DER')

        Returns:
            Tuple of (public_key_pem, public_key_obj)
        """
        try:
            if cert_format.upper() == 'PEM':
                cert_data = Path(cert_path).read_bytes()
                der_data = b64decode(''.join(cert_data.decode(encoding='utf-8').replace(" ", "").split('\n')[1:-1]))
            else:
                der_data = Path(cert_path).read_bytes()

            # Extract public key from certificate

            cert = DerSequence()
            cert.decode(der_data)
            tbs_cert = DerSequence()
            tbs_cert.decode(cert[0])
            public_key_info = tbs_cert[6]

            pub_key = RSA.import_key(public_key_info)
            return pub_key.publickey().export_key(), pub_key.publickey()

        except Exception as e:
            raise CryptoError(f"Failed to extract public key from: {cert_path}: {e}")

    @staticmethod
    def sign_data(
        data: Union[str, bytes],
        private_key_path: str,
        use_pkcs: bool = True
    ) -> bytes:
        """
        Sign data using a RSA private key

        Args:
            data: The data to sign
            private_key_path: Path to private key file to sign with
            use_pkcs: Whether to use PKCS#1 v1.5 signing

        Returns:
            Signature bytes
        """
        try:
            if isinstance(data, str):
                data = data.encode()

            # Load the private key
            with open(private_key_path, 'rb') as f:
                private_key = RSA.import_key(f.read())

            if use_pkcs:
                # PKCS#1 v1.5 signing with private key from X.509
                hash_obj = SHA256.new(data)
                signer = PKCS1_v1_5.new(private_key)
                signature = signer.sign(hash_obj)
            else:
                # Raw RSA signing otherwise
                hash_obj = SHA256.new(data).hexdigest().encode()
                signature = long_to_bytes(private_key.sign(hash_obj, '')[0])

            return signature

        except Exception as e:
            raise CryptoError(f"Signing failed: {e}")

    @staticmethod
    def verify_signature(
        data: Union[str, bytes],
        signature: bytes,
        public_key: RSA.RsaKey,
        use_pkcs: bool = True
    ) -> bool:
        """
        Verify signature using public key - RSA of JWT

        Args:
            data: Original signed data
            signature: Signature to verify, as bytes
            public_key: The public key object for verification
            use_pkcs: Whether to use PKCS#1 v1.5 default verification

        Returns:
            True if signature is valid
            Exception if not valid
        """
        try:
            if isinstance(data, str):
                data = data.encode()

            if use_pkcs:
                # PKCS#1 v1.5 verification method
                hash_obj = SHA256.new(data)
                verifier = PKCS1_v1_5.new(public_key)
                if verified := verifier.verify(hash_obj, signature):
                    return True
                raise CryptoError(f"Verification failed")
            else:
                try:
                    hash_obj = SHA256.new(data)
                    pkcs1_15.new(public_key).verify(hash_obj, signature)
                    return True
                except ValueError as ex:
                    raise CryptoError(f"Verification failed: {e}")

        except Exception as e:
            raise CryptoError(f"Verification failed: {e}")

    @staticmethod
    def create_jwt_signature(header, payload, secret_key) -> bytes:
        try:
            # Step 1. URL safe encode header and payload
            encoded_header = urlsafe_b64encode(header)
            encoded_payload = urlsafe_b64encode(payload)

            # Step 2. Create the message string with period separator. This is what
            # we are signing
            message = encoded_header + b'.' + encoded_payload

            # STep 3. Create HMAC-SHA256 signature over the message
            signature = hmac.new(
                secret_key.encode('utf-8'),
                message,
                hashlib.sha256
            ).digest()
            return signature
        except Exception as e:
            raise CryptoError(f"Signature creation failed: {e}")


"""Info...

    keydata = ['n', 'e', 'd', 'p', 'q', 'u']

    keydata
    Dictionary of RSA parameters.

    A public key will only have the following entries:

    n, the modulus.
    e, the public exponent.
    A private key will also have:

    d, the private exponent.
    p, the first factor of n.
    q, the second factor of n.
    u, the CRT coefficient (1/p) mod q.


TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

        http://docs.ganeti.org/ganeti/2.8/html/design-x509-ca.html

"""


def fetch_jwks(url: Optional[Union[str, None]]) -> Optional[JWKSType]:
    """
    Fetches the JWKS (JSON Web Key Set) from a token endpoint or
    falls back to Auth0's sample endpoint for example.

    Returns:
        Dict: The JWKS as a dictionary if successful
        None: If the request fails

    Raises:
        requests.RequestException: If there's a network error getting the keys
    """
    jwks_url = url or "https://samples.auth0.com/.well-known/jwks.json"

    try:
        response = requests.get(jwks_url)
        response.raise_for_status()

        return response.json()

    except requests.RequestException as e:
        plog({"msg": f"Error fetching JWKS: {str(e)}"})
        return None


def maybe_pad(s) -> str:
    return (s + '=' * (4 - len(s) % 4))


def get_token_segments(token) -> TokenSegments:
    """
    A valid token will have at least two seqments. Segments are delimited by
    a period '.'
    """
    header, payload, signature = token.split(".")

    """
    The JWT spec tells us the header MUST be urlsafe B64 encoded. Decode it
    but first add any padding (by adding one or more =) that may be needed

    https://tools.ietf.org/html/rfc7519

    Get the header json object that was stringified, it will be returned a
    string of bytes
    """
    header_json_str = urlsafe_b64decode(maybe_pad(header))

    """
    get the payload json object that was stringified, it will be returned a
    string of bytes
    """

    payload_json_str = urlsafe_b64decode(maybe_pad(payload))

    """
    get the signature that was stringified, it will be returned a string of
    bytes. It is not an object but rather the signature byte string, so full
    of non plogable characters
    """

    signature_bytes = urlsafe_b64decode(maybe_pad(signature))

    """
    convert header and payload back into objects. The signature is already
    a byte string


    NB: The order of the keys in the dict/object that results from the
    json.loads call will not be ordered in any way so watch out if you
    expect the transformations to be reversable

    object -> json.dumps -> string  <==> string -> json.loads -> object

    This can trip you up if you decode a header and payload, then try to recode
    it and expect the signature to work out.
    """

    header_json = json.loads(header_json_str)
    payload_json = json.loads(payload_json_str)
    return header_json, payload_json, signature_bytes


def get_EXP(token) -> str:
    payload_json = get_token_segments(token)[1]
    exp = payload_json.get('exp')
    plog(json.dumps({"payload": payload_json}))
    if False:
        plog("Time now: %s" % (time.strftime('%Y-%m-%d %H:%M:%S',
                                             time.localtime(time.time()))))
        plog("Expires:  %s" % (time.strftime('%Y-%m-%d %H:%M:%S',
                                             time.localtime(exp))))
    return exp


def get_AUD(token) -> str:
    payload_json = get_token_segments(token)[1]
    aud = payload_json.get('aud')
    return aud


def get_ISS(token) -> str:
    payload_json = get_token_segments(token)[1]
    iss = payload_json.get('iss', 'https://cognito-identity.amazonaws.com')
    return iss


def get_ALG(token) -> str:
    header_json = get_token_segments(token)[0]
    alg = header_json.get('alg', 'RS256')
    return alg


def get_KID(token) -> str:
    header_json = get_token_segments(token)[0]
    kid = header_json.get('kid')
    return kid


def get_modulus_and_exponent(jwk_sets, kid, algorithm, force_fail=False):
    # plog("Looking for kid=%s algo=%s in the jwt key sets" % (kid, algorithm))
    for jwks in jwk_sets['keys']:
        if (force_fail and jwks['kid'] != kid) or (jwks['kid'] == kid and
                                                   jwks['alg'] == algorithm):
            e_b64 = jwks['e']
            n_b64 = jwks['n']
            e_bytes = base64.urlsafe_b64decode(maybe_pad(e_b64))
            n_bytes = base64.urlsafe_b64decode(maybe_pad(n_b64))
            exponent = bytes_to_long(e_bytes)
            modulus = bytes_to_long(n_bytes)
            return modulus, exponent


def get_jwks_json(token) -> JWKSType:
    iss = get_ISS(token)
    url = f"{iss}{'.well-known/jwks.json'}"
    hfn = sha256(url)
    if not os.path.exists(f"/tmp/{hfn}"):
        if r := fetch_jwks(url):
            with open("/tmp/%s" % (hfn), "w") as outfile:
                outfile.write(json.dumps(r))
                return r
    else:
        with open(f"/tmp/{hfn}", "r") as infile:
            return json.loads(infile.read())


def construct_RSA_publickey(modulus, exponent):
    publicKey = RSA.construct((modulus, exponent))
    return publicKey.publickey().exportKey(), publicKey.publickey()


def main(token) -> None:
    """ the upstream base64 decode routines expect sr types so convert if needed """

    if isinstance(token, bytes):
        token = token.encode('utf-8')

    """
    Extract the KeyID and some other useful information to validate the token.

    See...

    http://self-issued.info/docs/draft-jones-json-web-token-01.html#ReservedClaimName

    Note: For other than this demo case, in real world uses we would obviously not
    check the validity of AUD, ISS against itself but rather values you expect


    """
    kid = get_KID(token)
    alg = get_ALG(token)
    aud = get_AUD(token)
    exp = get_EXP(token)
    iss = get_ISS(token)


    """
    The JWT is digitally signed by the private key
    half of the ISSUERS RSA key pair. We can find who the ISSUER
    was by looking for the 'iss' key in payload.  To verify the token
    signature there are a few basic steps.

    Step 1:

    Get the corrosponding Public Key half of the RSA key pair that
    signed the token.

    We get it from the URL addressed via:

    ISS + '/.well-known/jwks_uri'
    eg: https://cognito-identity.amazonaws.com/.well-known/jwks_uri
    """

    jwk_sets = get_jwks_json(token)
    plog(json.dumps({"jwk_sets": jwk_sets}))


    """
    The particular key we want is the key set that matches the 'kid' in the
    token header.  It'll look something like this:

    {
        "kty": "RSA",
        "alg": "RS512",
        "use": "sig",
        "kid": "ap-southeast-22",
        "n": "AJZzNUBnF1H6rFFiqJbiziWW7VVbyo............Ws35b7",
        "e": "AQAB"
    }

    Step 2:

    Note the key type and hash algorithm. Extract the modulus
    (the n value) and the exponent (the e value) from the key set
    """

    modulus, exponent = get_modulus_and_exponent(jwk_sets, kid, alg)

    """ Using the modulus and exponent construct the Public key and
    return it in PEM format. It will look something like this:

    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi8sT+HiH1d0BXLLQLt+f
    Vldnca3phPYs+weygJQaA8BUmcsmM9GPd1IjZSaVZotpxKgdh4UAF/GPxhE6cT1+
    mIa2jktx3J+5EoRP02/lRpmnSQxJKgXvBeKenTsAJRuf5kTciZBHXqvX9D+PcAPg
    KY3uBWOTn4RnNUJNC0DMlknz8SAI8UThgDRDZSAW0GNme3hIjxOWOKQGpSY0NUrK
    OHbIj6bh9A78tk4Roj9oY5Zh6fhGs77/eFNiTvdv6gUI+cinWws1SZ0AfOMiBZgI
    LaoHAL61FaLvTrl5rYpiP6Q00V69cVgyumHdTWbGoNlLMg68RciVmqWE6g5zk2ZY
    xwIDAQAB
    -----END PUBLIC KEY-----
    """

    pem, publicKey = construct_RSA_publickey(modulus, exponent)

    """

    Step 3a

    Using the pyjwt module we can now try to decode & verify the token
    #pip install pyjwt

    Use the correct AUD, PEM etc., values below as required. In this case they will
    always be right because we just extrated from the token itself.

    """
    payload_decoded_and_verified = jwt.decode(token, pem, audience=aud,
                                            algorithms=[alg], verify=True)

    """
    possible errors/exceptions from pyjwt

    jwt.exceptions.ExpiredSignatureError: Signature has expired
    see the u'exp': 1483323209 value in the payload

    jwt.exceptions.DecodeError: Signature verification failed
    """

    if payload_decoded_and_verified:
        plog(json.dumps({"jwt.decode": "verify successful", "payload": payload_decoded_and_verified}))
    else:
        plog(json.dumps({"jwt.decode": "verify failed"}))

    
    """

    Or, alternatively, using the PKCS1_v1_5 module you can also verify it.

    Step 3b

    Note: One thing to watch out for here is that the order of the keys in the
    header payload matters, so if you decode a header from a token to a dict eg
    dict = json.loads(base64.urlsafe_b64decode(header)) and then encode it back
    the order of the keys may be different as a python dict is unordered

    With that in mind,  using PKCS1_v1_5 we can try to verify
    """

    header_base64 = token.split(".")[0]
    payload_base64 = token.split(".")[1]
    _, payload_json, signature_bytes = get_token_segments(token)

    # It is the header + payload that get originally signed, see the
    # SignatureManager.create_jwt_signature function above for how ...
    # Basically
    # jwt = f"{base64url_encode(header)}.{base64url_encode(payload)}.{signature}"

    # we want to verify header + payload
    data_to_verify = f"{header_base64}.{payload_base64}".encode()

    try:
        # Signature Verification method 2
        verified = SignatureManager.verify_signature(data_to_verify, signature_bytes, publicKey, use_pkcs=True)
        plog(json.dumps({"jwt.decode.pkcs1_v1_5.1": "verify successful", "payload": payload_json}))
    except Exception as ex:
        plog(json.dumps({"jwt.decode.pkcs1_v1_5.1": "verify failed"}))

    try:
        # Signature Verification method 3
        verified = SignatureManager.verify_signature(data_to_verify, signature_bytes, publicKey, use_pkcs=False)
        plog(json.dumps({"jwt.decode.pkcs1_v1_5.2": "verify successful", "payload": payload_json}))
    except Exception as ex:
        plog(json.dumps({"jwt.decode.pkcs1_v1_5.2": "verify failed"}))
    pass


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '--token',
            help='a JWT or JWS token.',
            required=False,
            type=str,
            default=os.environ.get("ID_TOKEN"))
        args = parser.parse_args()

        main(args.token)
    except Exception as ex:
        plog(json.dumps({"msg": f"{ex}"}))
