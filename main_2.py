from flask import Flask, request, jsonify
from google.cloud import datastore

# Username-Password-Authentication
# password1.xyz

# domain, dev-mhuy7ewvs3ucy4hh.us.auth0.com
# client id, hpeg00KD8CtCVEqdb41zGzUhQRGKWsAt
# client secret, 9BRG--1t5EheUo11WRCJw76PIa58VfsYeavui4mS_N355tbf7EtwTEmDTc2muEgn

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

LODGINGS = "lodgings"

# Update the values of the following 3 variables
CLIENT_ID = 'hpeg00KD8CtCVEqdb41zGzUhQRGKWsAt'
CLIENT_SECRET = '9BRG--1t5EheUo11WRCJw76PIa58VfsYeavui4mS_N355tbf7EtwTEmDTc2muEgn'
DOMAIN = 'dev-mhuy7ewvs3ucy4hh.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

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

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

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

############################################################################################################
BASE_URL = 'http://127.0.0.1:8080'
#BASE_URL = "https://cs493-a5-2.uc.r.appspot.com"

# a5

@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"

# TODO: modify.

# Create a lodging if the Authorization header contains a valid JWT
@app.route('/lodgings', methods=['POST'])
def lodgings_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_lodging = datastore.entity.Entity(key=client.key(LODGINGS))
        new_lodging.update({"name": content["name"], "description": content["description"],
          "price": content["price"]})
        client.put(new_lodging)
        return jsonify(id=new_lodging.key.id)
    else:
        return jsonify(error='Method not recogonized')
    
# Generate a JWT

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def generate_a_jwt(): # Copied from the explorations.
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}

# Decode a JWT

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_a_jwt(): # Copied from the explorations.
    payload = verify_jwt(request)
    return payload

# Create a Business
@app.route('/businesses', methods=['POST'])
def create_a_business():

    # Get the content.
    content = request.get_json()

    # TODO: Check for missing required fields
    required_fields = ["name", "street_address", "city", "state", "zip_code", "inspection_score"]
    for field in required_fields:
        if field not in content:
            return jsonify(Error="The request body is missing at least one of the required attributes"), 400
    
    # Decode the token.
    payload = verify_jwt(request)

    # Check if the token is valid.
    if not payload:
        return jsonify(Error="Invalid token"), 401
    
    # Generate entity.
    user_id = payload["sub"]
    new_business = datastore.entity.Entity(key=client.key("businesses"))
    new_business.update({
        "owner_id": user_id,
        "name": content["name"],
        "street_address": content["street_address"],
        "city": content["city"],
        "state": content["state"],
        "zip_code": content["zip_code"],
        "inspection_score": content["inspection_score"]
    })

    # Save entity.
    client.put(new_business)

    # Generate response.
    response = {
        "id": new_business.id,
        "owner_id": user_id,
        "name": content["name"],
        "street_address": content["street_address"],
        "city": content["city"],
        "state": content["state"],
        "zip_code": content["zip_code"],
        "inspection_score": content["inspection_score"],
        "self": BASE_URL + "/businesses/" + str(new_business.id)
    }

    return jsonify(response), 201

# Get a Business
@app.route('/businesses/<int:business_id>', methods=['GET'])
def get_business(business_id):
    # Decode the token
    payload = verify_jwt(request)

    # Check if the token is valid
    if not payload:
        return jsonify(Error="Invalid or missing JWT"), 401

    user_id = payload["sub"]

    # Retrieve the business
    business_key = client.key("businesses", business_id)
    business = client.get(key=business_key)

    # Check if the business exists
    if not business:
        return jsonify(Error="No business with this business_id exists"), 403

    # Check if the user is the owner
    if business["owner_id"] != user_id:
        return jsonify(Error="You do not have permission to view this business"), 403

    # Prepare the response
    response = {
        "id": business.key.id,
        "owner_id": business["owner_id"],
        "name": business["name"],
        "street_address": business["street_address"],
        "city": business["city"],
        "state": business["state"],
        "zip_code": business["zip_code"],
        "inspection_score": business["inspection_score"],
        "self": BASE_URL + "/businesses/" + str(business.key.id)
    }

    return jsonify(response), 200

# List Businesses
@app.route('/businesses', methods=['GET'])
def list_businesses():
    # Decode the token
    payload = verify_jwt(request)

    business_list = []

    if payload:
        # Valid JWT provided
        user_id = payload["sub"]
        # Query businesses owned by the user
        query = client.query(kind="businesses")
        query.add_filter("owner_id", "=", user_id)
        businesses = list(query.fetch())

        for business in businesses:
            business_list.append({
                "id": business.key.id,
                "owner_id": business["owner_id"],
                "name": business["name"],
                "street_address": business["street_address"],
                "city": business["city"],
                "state": business["state"],
                "zip_code": business["zip_code"],
                "inspection_score": business["inspection_score"],
                "self": BASE_URL + "/businesses/" + str(business.key.id)
            })
    else:
        # No valid JWT provided; list all businesses without inspection_score
        query = client.query(kind="businesses")
        businesses = list(query.fetch())

        for business in businesses:
            business_list.append({
                "id": business.key.id,
                "owner_id": business["owner_id"],
                "name": business["name"],
                "street_address": business["street_address"],
                "city": business["city"],
                "state": business["state"],
                "zip_code": business["zip_code"],
                "self": BASE_URL + "/businesses/" + str(business.key.id)
            })

    return jsonify(business_list), 200

# Delete a Business
@app.route('/businesses/<int:business_id>', methods=['DELETE'])
def delete_business(business_id):
    # Decode the token
    payload = verify_jwt(request)

    # Check if the token is valid
    if not payload:
        return jsonify(Error="Invalid or missing JWT"), 401

    user_id = payload["sub"]

    # Retrieve the business
    business_key = client.key("businesses", business_id)
    business = client.get(key=business_key)

    # Check if the business exists
    if not business:
        return jsonify(Error="No business with this business_id exists"), 403

    # Check if the user is the owner
    if business["owner_id"] != user_id:
        return jsonify(Error="You do not have permission to delete this business"), 403

    # Delete the business
    client.delete(business_key)

    return '', 204

"""# Get a Business
@app.route('/businesses/<business_id>', methods=['GET'])
def get_a_business(business_id):
    pass
# List Businesses
@app.route('/businesses', methods=['GET'])
def list_businesses():
    pass
# Delete a Business
@app.route('/businesses/<business_id>', methods=['DELETE'])
def delete_a_business():
    pass"""

############################################################################################################

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)