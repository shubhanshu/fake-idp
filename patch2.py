p = "/tmp/fake-idp-repo/app.py"
s = open(p).read()

def repl(old, new):
    global s
    n = s.count(old)
    assert n == 1, f"anchor count {n} (want 1):\n{old!r}"
    s = s.replace(old, new)

# Support client_secret_basic (Authorization: Basic base64(client_id:client_secret)),
# which the discovery doc already advertises. Databricks sends client auth this way,
# not in the token request body — without this the id_token aud falls back to
# 'default_client' and relying-party aud validation fails.
repl(
    "# Token endpoint\n@app.route('/token', methods=['POST'])",
    "def _client_id_from_basic_auth():\n"
    "    \"\"\"Extract client_id from an HTTP Basic Authorization header, if present.\"\"\"\n"
    "    header = request.headers.get('Authorization', '')\n"
    "    if header.startswith('Basic '):\n"
    "        try:\n"
    "            decoded = base64.b64decode(header[len('Basic '):]).decode('utf-8')\n"
    "            return decoded.split(':', 1)[0]\n"
    "        except Exception:\n"
    "            return None\n"
    "    return None\n\n"
    "# Token endpoint\n@app.route('/token', methods=['POST'])",
)

repl(
    "        code = request.form.get('code')\n"
    "        client_id = request.form.get('client_id')\n"
    "        redirect_uri = request.form.get('redirect_uri')",
    "        code = request.form.get('code')\n"
    "        client_id = request.form.get('client_id') or _client_id_from_basic_auth()\n"
    "        redirect_uri = request.form.get('redirect_uri')",
)

import ast
ast.parse(s)
open(p, "w").write(s)
print("patched OK (%d bytes)" % len(s))
