# JWT Token Verification Tool

A robust Python tool for verifying and decoding JWT (JSON Web Token) tokens using multiple verification methods including PyJWT and PKCS1_v1_5. Particularly useful for verifying tokens from OAuth/OIDC providers like Auth0, AWS Cognito, etc.

## Features

- Multiple verification methods (PyJWT, PKCS1_v1_5)
- JWKS (JSON Web Key Set) fetching and caching
- RSA public/private key pair generation
- X.509 certificate operations
- Digital signature verification
- Support for both PEM and DER formats
- JSON output for easy integration

## Installation

### Prerequisites

```bash
python3 -m pip install -r requirements.txt
```

Required packages:
```
pyjwt
cryptography
pycryptodome
pyOpenSSL
requests
```

## Usage

### Basic Token Verification

```bash
python3 jwt_verify.py --token "your.jwt.token"
```

Or using environment variable:
```bash
export ID_TOKEN="your.jwt.token"
python3 jwt_verify.py
```

### Example Output

```json
{
  "payload": {
    "iss": "https://samples.auth0.com/",
    "sub": "auth0|123456789",
    "aud": "your-client-id",
    "exp": 1731415707,
    "iat": 1731379707
  },
  "jwt.decode": "verify successful"
}
```

### Using as a Module

```python
from jwt_verify import JWTVerifier, CertificateManager

# Create certificate manager
cert_manager = CertificateManager()

# Verify a token
token = "your.jwt.token"
claims = JWTVerifier.extract_claims(token)
jwks = JWTVerifier.fetch_jwks(f"{claims['iss']}.well-known/jwks.json")

# The verified payload will contain the decoded token contents
verified_payload = JWTVerifier.verify_token(
    token,
    public_key_pem,
    claims['aud'],
    claims['alg']
)
```

## Advanced Features

### Certificate Operations

```python
# Generate RSA key pair
cert_manager = CertificateManager(base_dir="./keys")
priv_key, pub_key = cert_manager.generate_rsa_keypair(
    name="mycert",
    bits=2048
)

# Create self-signed certificate
cert_path, key_path, pub_path = cert_manager.create_self_signed_cert(
    name="mycert.crt",
    days_valid=7
)
```

### Custom Key Verification

```python
from jwt_verify import SignatureManager

# Verify using PKCS1_v1_5
verified = SignatureManager.verify_signature(
    data=data_to_verify,
    signature=signature_bytes,
    public_key=public_key,
    use_pkcs=True
)
```

## Implementation Details

The tool supports multiple verification methods:

1. **PyJWT Verification**: Uses the `pyjwt` library for standard JWT verification
2. **PKCS1_v1_5 Verification**: Implements direct RSA signature verification
3. **Raw RSA Verification**: Provides low-level signature verification

Key features:
- Automatic JWKS caching in `/tmp/`
- Support for multiple signature algorithms (RS256, RS384, RS512)
- Proper handling of padding in base64url encoding
- Comprehensive error handling and logging
- JSON-formatted output for easy parsing

## Security Considerations

- Always verify tokens using the correct audience (`aud`) claim
- Check token expiration (`exp`) claim
- Verify the issuer (`iss`) claim matches your expected identity provider
- Use HTTPS for fetching JWKS
- Don't trust tokens without signature verification

## Error Handling

Common errors and their meanings:

```python
try:
    payload = verify_token(token)
except jwt.ExpiredSignatureError:
    print("Token has expired")
except jwt.InvalidTokenError:
    print("Token is invalid")
except CryptoError as e:
    print(f"Cryptographic operation failed: {e}")
```

## Contributing

Feel free to submit issues and pull requests for:
- Additional verification methods
- Support for more token formats
- Performance improvements
- Bug fixes
- Documentation improvements

## License

MIT License - see LICENSE file for details.