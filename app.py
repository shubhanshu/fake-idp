import os
from flask import Flask, request, jsonify, render_template_string, redirect, session, url_for
import jwt
import datetime
import uuid
import secrets
import hashlib
import base64
from urllib.parse import urlencode, parse_qs, urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
ISSUER = os.environ.get("FAKE_IDP_ISSUER", "http://localhost:5000")
ALLOWED_USER = "xiaoyi.zhang@databricks.com"
ALLOWED_PASSWORD = "password123"  # Simple password for demo

# Ephemeral RSA signing key generated at startup (no secret committed to source).
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

_signing_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_KEY = _signing_key.private_bytes(
    encoding=_serialization.Encoding.PEM,
    format=_serialization.PrivateFormat.PKCS8,
    encryption_algorithm=_serialization.NoEncryption(),
).decode()
PUBLIC_KEY = _signing_key.public_key().public_bytes(
    encoding=_serialization.Encoding.PEM,
    format=_serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

# Key ID for JWKS
KEY_ID = "rsa-key-1"

# In-memory storage for authorization codes and tokens
auth_codes = {}
refresh_tokens = {}

# OIDC Discovery endpoint
@app.route('/.well-known/openid-configuration')
def openid_configuration():
    """OIDC Discovery document"""
    config = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code", "token", "id_token"],
        "grant_types_supported": ["authorization_code", "refresh_token", "password", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "name", "email", "iss", "aud", "exp", "iat"]
    }
    return jsonify(config)

# Authorization endpoint
@app.route('/authorize')
def authorize():
    """OIDC Authorization endpoint - presents login page"""
    # Get query parameters
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    response_type = request.args.get('response_type', 'code')
    scope = request.args.get('scope', 'openid')
    state = request.args.get('state', '')
    nonce = request.args.get('nonce', '')
    
    # Store in session for after login
    session['auth_request'] = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'scope': scope,
        'nonce': nonce,
        'state': state
    }
    
    # Check if already logged in
    if session.get('user'):
        return redirect(url_for('authorize_callback'))
    
    # Show login page
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/login', methods=['POST'])
def login():
    """Handle login form submission"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == ALLOWED_USER and password == ALLOWED_PASSWORD:
        session['user'] = username
        return redirect(url_for('authorize_callback'))
    else:
        return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")

@app.route('/authorize/callback')
def authorize_callback():
    """Process authorization after successful login"""
    if 'user' not in session:
        return redirect(url_for('authorize'))
    
    auth_request = session.get('auth_request', {})
    redirect_uri = auth_request.get('redirect_uri')
    state = auth_request.get('state', '')
    
    if not redirect_uri:
        return "Error: Missing redirect_uri", 400
    
    # Generate authorization code
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        'user': session['user'],
        'client_id': auth_request.get('client_id'),
        'scope': auth_request.get('scope'),
        'nonce': auth_request.get('nonce'),
        'expires': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    
    # Build redirect URL with code
    params = {'code': code}
    if state:
        params['state'] = state
    
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    return redirect(redirect_url)

def _client_id_from_basic_auth():
    """Extract client_id from an HTTP Basic Authorization header, if present."""
    header = request.headers.get('Authorization', '')
    if header.startswith('Basic '):
        try:
            decoded = base64.b64decode(header[len('Basic '):]).decode('utf-8')
            return decoded.split(':', 1)[0]
        except Exception:
            return None
    return None

# Token endpoint
@app.route('/token', methods=['POST'])
def token():
    """OIDC Token endpoint - exchange code for tokens"""
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        client_id = request.form.get('client_id') or _client_id_from_basic_auth()
        redirect_uri = request.form.get('redirect_uri')
        
        # Validate authorization code
        if code not in auth_codes:
            return jsonify({"error": "invalid_grant"}), 400
        
        auth_data = auth_codes[code]
        
        # Check expiration
        if datetime.datetime.utcnow() > auth_data['expires']:
            del auth_codes[code]
            return jsonify({"error": "invalid_grant"}), 400
        
        # Delete used code
        del auth_codes[code]
        
        # Generate tokens
        user = auth_data['user']
        access_token = generate_access_token(user, client_id)
        id_token = generate_id_token(user, client_id, auth_data.get('nonce'))
        refresh_token_str = secrets.token_urlsafe(32)
        
        # Store refresh token
        refresh_tokens[refresh_token_str] = {
            'user': user,
            'client_id': client_id,
            'expires': datetime.datetime.utcnow() + datetime.timedelta(days=30)
        }
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
            "refresh_token": refresh_token_str
        })
    
    elif grant_type == 'refresh_token':
        refresh_token_str = request.form.get('refresh_token')
        
        if refresh_token_str not in refresh_tokens:
            return jsonify({"error": "invalid_grant"}), 400
        
        refresh_data = refresh_tokens[refresh_token_str]
        
        # Check expiration
        if datetime.datetime.utcnow() > refresh_data['expires']:
            del refresh_tokens[refresh_token_str]
            return jsonify({"error": "invalid_grant"}), 400
        
        user = refresh_data['user']
        client_id = refresh_data['client_id']
        
        # Generate new tokens
        access_token = generate_access_token(user, client_id)
        id_token = generate_id_token(user, client_id)
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token
        })
    
    elif grant_type == 'password':
        # Resource Owner Password Credentials grant
        username = request.form.get('username')
        password = request.form.get('password')
        client_id = request.form.get('client_id', 'password_grant_client')
        scope = request.form.get('scope', '')
        
        # Validate credentials
        if username != ALLOWED_USER or password != ALLOWED_PASSWORD:
            return jsonify({"error": "invalid_grant", "error_description": "Invalid username or password"}), 400
        
        # Generate tokens
        access_token = generate_access_token(username, client_id)
        id_token = generate_id_token(username, client_id)
        refresh_token_str = secrets.token_urlsafe(32)
        
        # Store refresh token
        refresh_tokens[refresh_token_str] = {
            'user': username,
            'client_id': client_id,
            'expires': datetime.datetime.utcnow() + datetime.timedelta(days=30)
        }
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
            "refresh_token": refresh_token_str,
            "scope": scope
        })
    
    elif grant_type == 'client_credentials':
        # Client Credentials grant - using password as credential
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        scope = request.form.get('scope', 'openid profile email')
        
        # Validate client credentials (using password as the secret)
        if client_secret != ALLOWED_PASSWORD:
            return jsonify({"error": "invalid_client", "error_description": "Invalid client credentials"}), 401
        
        # For client_credentials, we use a service account identity
        # Using the allowed user as the subject
        service_identity = ALLOWED_USER
        
        # Generate access token (no ID token or refresh token for client_credentials)
        access_token = generate_access_token(service_identity, client_id or 'client_credentials_client')
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope
        })
    
    return jsonify({"error": "unsupported_grant_type"}), 400

# UserInfo endpoint
@app.route('/userinfo')
def userinfo():
    """OIDC UserInfo endpoint - returns user information"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "invalid_token"}), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])
        
        return jsonify({
            "sub": payload.get('sub'),
            "name": payload.get('name'),
            "email": payload.get('email'),
            "email_verified": True
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token_expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid_token"}), 401

# JWKS endpoint (for token verification)
@app.route('/jwks')
def jwks():
    """JSON Web Key Set endpoint"""
    # Extract the modulus (n) and exponent (e) from the public key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    public_key_obj = serialization.load_pem_public_key(
        PUBLIC_KEY.encode(),
        backend=default_backend()
    )
    
    # Get public numbers
    public_numbers = public_key_obj.public_numbers()
    
    # Convert to base64url encoding
    def int_to_base64url(num):
        num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
        return base64.urlsafe_b64encode(num_bytes).rstrip(b'=').decode('utf-8')
    
    n = int_to_base64url(public_numbers.n)
    e = int_to_base64url(public_numbers.e)
    
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": KEY_ID,
        "alg": "RS256",
        "n": n,
        "e": e
    }
    
    return jsonify({"keys": [jwk]})

# Keys endpoint (to view the keys easily)
@app.route('/keys')
def keys_page():
    """Display public and private keys"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>RSA Keys</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                background: #f5f5f5;
                margin: 0;
                padding: 40px 20px;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            }
            h1 {
                color: #333;
                margin: 0 0 10px 0;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
            }
            .key-section {
                margin: 30px 0;
            }
            .key-title {
                font-weight: 600;
                color: #333;
                margin-bottom: 10px;
                font-size: 18px;
            }
            .key-box {
                background: #f8f9fa;
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                padding: 15px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-all;
                color: #333;
            }
            .warning {
                background: #fff3cd;
                border: 1px solid #ffc107;
                border-radius: 6px;
                padding: 15px;
                margin-bottom: 20px;
                color: #856404;
            }
            .info {
                background: #d1ecf1;
                border: 1px solid #17a2b8;
                border-radius: 6px;
                padding: 15px;
                margin-top: 20px;
                color: #0c5460;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔑 RSA Keys</h1>
            <p class="subtitle">Public and Private Keys for Token Signing</p>
            
            <div class="warning">
                ⚠️ <strong>Warning:</strong> These are hardcoded keys for testing only. Never use these in production!
            </div>
            
            <div class="key-section">
                <div class="key-title">🔓 Public Key (Share this with clients for token verification)</div>
                <div class="key-box">{{ public_key }}</div>
            </div>
            
            <div class="key-section">
                <div class="key-title">🔐 Private Key (Keep this secret!)</div>
                <div class="key-box">{{ private_key }}</div>
            </div>
            
            <div class="info">
                <strong>Key Information:</strong><br>
                • Algorithm: RS256 (RSA with SHA-256)<br>
                • Key Size: 2048 bits<br>
                • Key ID (kid): {{ key_id }}<br>
                • Format: PEM (PKCS#8)<br>
                • Use: Token signing and verification
            </div>
        </div>
    </body>
    </html>
    """, public_key=PUBLIC_KEY, private_key=PRIVATE_KEY, key_id=KEY_ID)

# Logout endpoint
@app.route('/logout')
def logout():
    """Logout endpoint"""
    session.clear()
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logged Out</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 50px; background: #f0f0f0; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h2 { color: #333; text-align: center; }
            .message { text-align: center; color: #666; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Logged Out</h2>
            <p class="message">You have been successfully logged out.</p>
        </div>
    </body>
    </html>
    """)

# Helper functions
def generate_access_token(user, client_id):
    """Generate JWT access token"""
    now = datetime.datetime.utcnow()
    payload = {
        'sub': user,
        'email': user,
        'name': user.split('@')[0].replace('.', ' ').title(),
        'iss': ISSUER,
        'aud': client_id or 'default_client',
        'iat': now,
        'exp': now + datetime.timedelta(hours=1),
        'jti': str(uuid.uuid4())
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm='RS256', headers={'kid': KEY_ID})

def generate_id_token(user, client_id, nonce=None):
    """Generate OIDC ID token"""
    now = datetime.datetime.utcnow()
    payload = {
        'sub': user,
        'email': user,
        'email_verified': True,
        'name': user.split('@')[0].replace('.', ' ').title(),
        'iss': ISSUER,
        'aud': client_id or 'default_client',
        'iat': now,
        'exp': now + datetime.timedelta(hours=1),
        'auth_time': int(now.timestamp())
    }
    if nonce:
        payload['nonce'] = nonce
    return jwt.encode(payload, PRIVATE_KEY, algorithm='RS256', headers={'kid': KEY_ID})

# Login page template
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Fake IDP - Login</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        h2 {
            margin: 0 0 10px 0;
            color: #333;
            text-align: center;
            font-size: 28px;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            box-sizing: border-box;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(0);
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
            border: 1px solid #fcc;
        }
        .demo-info {
            margin-top: 25px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
            font-size: 13px;
            color: #666;
        }
        .demo-info strong {
            color: #333;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>🔐 Fake IDP</h2>
        <p class="subtitle">OpenID Connect Provider</p>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username (Email)</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
        
        <div class="demo-info">
            <strong>Demo Credentials:</strong><br>
            Username: xiaoyi.zhang@databricks.com<br>
            Password: password123
        </div>
    </div>
</body>
</html>
"""

# Home page
@app.route('/')
def home():
    """Home page with IDP information"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fake IDP - Home</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                background: #f5f5f5;
                margin: 0;
                padding: 40px 20px;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            }
            h1 {
                color: #333;
                margin: 0 0 10px 0;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
            }
            .endpoint {
                background: #f8f9fa;
                padding: 15px;
                margin: 10px 0;
                border-radius: 6px;
                border-left: 4px solid #667eea;
            }
            .endpoint-title {
                font-weight: 600;
                color: #333;
                margin-bottom: 5px;
            }
            .endpoint-url {
                font-family: 'Courier New', monospace;
                color: #667eea;
                font-size: 14px;
            }
            .section {
                margin-top: 30px;
            }
            code {
                background: #f0f0f0;
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Fake IDP (OpenID Connect Provider)</h1>
            <p class="subtitle">A simple OIDC-compliant Identity Provider for testing</p>
            
            <div class="section">
                <h2>OIDC Endpoints</h2>
                
                <div class="endpoint">
                    <div class="endpoint-title">Discovery Document</div>
                    <div class="endpoint-url">GET /.well-known/openid-configuration</div>
                </div>
                
                <div class="endpoint">
                    <div class="endpoint-title">Authorization Endpoint</div>
                    <div class="endpoint-url">GET /authorize</div>
                </div>
                
                <div class="endpoint">
                    <div class="endpoint-title">Token Endpoint</div>
                    <div class="endpoint-url">POST /token</div>
                </div>
                
                <div class="endpoint">
                    <div class="endpoint-title">UserInfo Endpoint</div>
                    <div class="endpoint-url">GET /userinfo</div>
                </div>
                
                <div class="endpoint">
                    <div class="endpoint-title">JWKS Endpoint</div>
                    <div class="endpoint-url">GET /jwks</div>
                </div>
                
                <div class="endpoint">
                    <div class="endpoint-title">RSA Keys (Public & Private)</div>
                    <div class="endpoint-url">GET /keys</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Test Credentials</h2>
                <p>
                    <strong>Username:</strong> <code>xiaoyi.zhang@databricks.com</code><br>
                    <strong>Password:</strong> <code>password123</code>
                </p>
            </div>
            
            <div class="section">
                <h2>Configuration</h2>
                <p>
                    <strong>Issuer:</strong> <code>{{ issuer }}</code><br>
                    <strong>Algorithm:</strong> <code>RS256</code> (RSA with SHA-256)<br>
                    <strong>Key ID:</strong> <code>rsa-key-1</code><br>
                    <strong>Keys:</strong> <a href="/keys" style="color: #667eea;">View RSA Keys</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    """, issuer=ISSUER)

if __name__ == '__main__':
    print("=" * 60)
    print("🔐 Fake IDP Server Starting...")
    print("=" * 60)
    print(f"Issuer: {ISSUER}")
    print(f"Discovery URL: {ISSUER}/.well-known/openid-configuration")
    print(f"\nSupported Grant Types:")
    print(f"  • Authorization Code Flow")
    print(f"  • Password Grant (ROPC)")
    print(f"  • Client Credentials")
    print(f"  • Refresh Token")
    print(f"\nTest Credentials:")
    print(f"  Username: {ALLOWED_USER}")
    print(f"  Password: {ALLOWED_PASSWORD}")
    print(f"  Client Secret: {ALLOWED_PASSWORD}")
    print(f"\nToken Signing:")
    print(f"  Algorithm: RS256")
    print(f"  Key ID: {KEY_ID}")
    print(f"\nEndpoints:")
    print(f"  Keys Page: {ISSUER}/keys")
    print(f"  JWKS: {ISSUER}/jwks")
    print("=" * 60)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=True)


