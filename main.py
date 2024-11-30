from flask import Flask, request, jsonify
from google.cloud import datastore
import requests
import json

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

#-auth0-#---------------------------------------------------------------
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
CLIENT_ID = 'hpeg00KD8CtCVEqdb41zGzUhQRGKWsAt'
CLIENT_SECRET = '9BRG--1t5EheUo11WRCJw76PIa58VfsYeavui4mS_N355tbf7EtwTEmDTc2muEgn'
DOMAIN = 'dev-mhuy7ewvs3ucy4hh.us.auth0.com'

ALGORITHMS = ["RS256"]
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
#-auth0-#---------------------------------------------------------------

# Endpoint 1: User Login.
@app.route('/users/login', methods=['POST'])
def user_login():
    content = request.get_json()
    if 'username' not in content or 'password' not in content:
        return jsonify({"Error": "The request body is invalid"}), 400
    username = content["username"]
    password = content["password"]
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    try:
        r = requests.post(url, json=body, headers=headers)
        r.raise_for_status()  # Raises an HTTPError if the response status code is 4XX/5XX
        token = r.json().get("id_token")
        return jsonify({"token": token}), 200
    except:
        return jsonify({"Error": "Unauthorized"}), 401

# Endpoint 2: Get all users.
@app.route('/users', methods=['GET'])
def get_users():
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        user_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401
    # Query the user with this sub
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())
    if not results:
        return jsonify({"Error": "The JWT is missing or invalid"}), 401
    user = results[0]
    if user.get('role') != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # User is admin, fetch all users
    query = client.query(kind='users')
    all_users = list(query.fetch())
    response = []
    for user_entity in all_users:
        user_info = {
            'id': user_entity.key.id,
            'role': user_entity.get('role'),
            'sub': user_entity.get('sub')
        }
        response.append(user_info)
    return jsonify(response), 200

# Test + Utilities.

# Test if the app is running on the correct location.
@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"

# Test if the database connection is working correctly, part 1.
@app.route('/test_datastore', methods=['GET'])
def test_datastore():
    # Create a new entity in the datastore
    key = client.key('TestEntity')
    entity = datastore.Entity(key=key)
    entity.update({
        'name': 'Test Name',
        'description': 'This is a test entity'
    })
    client.put(entity)
    return jsonify({"message": "Entity stored successfully"}), 200

# Test if the database connection is working correctly, part 2.
@app.route('/view_entities', methods=['GET'])
def view_entities():
    query = client.query(kind='TestEntity')
    results = list(query.fetch())
    entities = []
    for entity in results:
        entities.append({
            'id': entity.key.id,
            'name': entity['name'],
            'description': entity['description']
        })
    return jsonify(entities), 200

# Run the code.
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)