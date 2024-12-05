from flask import Flask, request, jsonify
from google.cloud import datastore
import requests
import json
from flask import send_file
import io

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

BUCKET_NAME = "bucket_2_sd"
BASE_URL = "http://127.0.0.1:8080"

client = datastore.Client()
from google.cloud import storage

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
        return jsonify({"Error": "Unauthorized"}), 401
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

# Endpoint 3.
@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user associated with the JWT
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        # The JWT is valid, but the user doesn't exist
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Convert user_id to integer
    try:
        user_id_int = int(user_id)
    except ValueError:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Check permissions
    if jwt_user.get('role') != 'admin' and jwt_user.key.id != user_id_int:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the user specified by user_id
    key = client.key('users', user_id_int)
    user = client.get(key)
    if not user:
        # The user doesn't exist
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Construct the response body
    response_body = {
        "id": user.key.id,
        "role": user.get('role'),
        "sub": user.get('sub')
    }

    # Add avatar_url if the user has an avatar
    if 'avatar' in user:
        response_body['avatar_url'] = "{}/users/{}/avatar".format(BASE_URL, user.key.id)

    # If the user role is 'instructor' or 'student', include 'courses' property
    if user.get('role') == 'instructor':
        response_body['courses'] = []
        # Query courses where 'instructor_id' == user.key.id
        query = client.query(kind='courses')
        query.add_filter('instructor_id', '=', user.key.id)
        courses = list(query.fetch())
        for course in courses:
            course_link = "{}/courses/{}".format(BASE_URL, course.key.id)
            response_body['courses'].append(course_link)
    elif user.get('role') == 'student':
        response_body['courses'] = []
        # Query courses where 'students' includes user.key.id
        query = client.query(kind='courses')
        query.add_filter('students', '=', user.key.id)
        courses = list(query.fetch())
        for course in courses:
            course_link = "{}/courses/{}".format(BASE_URL, course.key.id)
            response_body['courses'].append(course_link)

    # Return the response
    return jsonify(response_body), 200

# Endpoint 4.
@app.route('/users/<user_id>/avatar', methods=['POST'])
def upload_user_avatar(user_id):
    # Check if 'file' is in the request
    if 'file' not in request.files:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user associated with the JWT
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Convert user_id to integer
    try:
        user_id_int = int(user_id)
    except ValueError:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Check if JWT belongs to the user in the path parameter
    if jwt_user.key.id != user_id_int:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the user entity
    key = client.key('users', user_id_int)
    user = client.get(key)
    if not user:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    
    # Check if 'file' is in the request files
    if 'file' not in request.files:
        return ('The request body is invalid', 400)

    # Get the file from the request
    file_obj = request.files['file']

    # Create a storage client
    storage_client = storage.Client()

    # Get a handle on the bucket using get_bucket
    bucket = storage_client.get_bucket(BUCKET_NAME)  # Replace with your bucket name

    # Create a blob object with the desired name
    blob_name = f'avatars/{user_id}.png'
    blob = bucket.blob(blob_name)

    # Position the file_obj to its beginning
    file_obj.seek(0)

    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj, content_type='image/png')

    # Update the user entity to indicate the avatar exists
    user['avatar'] = blob_name
    client.put(user)

    # Construct the avatar URL
    avatar_url = f"{BASE_URL}/users/{user_id}/avatar"

    return jsonify({"avatar_url": avatar_url}), 200

# Endpoint 5.
@app.route('/users/<user_id>/avatar', methods=['GET'])
def get_user_avatar(user_id):
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Convert user_id to integer
    try:
        user_id_int = int(user_id)
    except ValueError:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Get the user associated with the JWT's sub
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Check if JWT belongs to the user in the path parameter
    if jwt_user.key.id != user_id_int:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the user entity specified by user_id
    key = client.key('users', user_id_int)
    user = client.get(key)
    if not user:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Check if the user has an avatar
    if 'avatar' not in user:
        return jsonify({"Error": "Not found"}), 404

    # Retrieve the avatar from Google Cloud Storage
    storage_client = storage.Client()
    bucket_name = BUCKET_NAME  # Replace with your bucket name
    bucket = storage_client.bucket(bucket_name)
    blob_name = user['avatar']
    blob = bucket.blob(blob_name)

    # Read the blob into bytes
    try:
        avatar_bytes = blob.download_as_bytes()
    except:
        return jsonify({"Error": "Not found"}), 404

    # Create a BytesIO stream
    avatar_stream = io.BytesIO(avatar_bytes)

    # Return the avatar file
    return send_file(avatar_stream, mimetype='image/png'), 200

# Endpoint 6.
@app.route('/users/<user_id>/avatar', methods=['DELETE'])
def delete_user_avatar(user_id):
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Convert user_id to integer
    try:
        user_id_int = int(user_id)
    except ValueError:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Get the user associated with the JWT's sub
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Check if JWT belongs to the user in the path parameter
    if jwt_user.key.id != user_id_int:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the user entity specified by user_id
    key = client.key('users', user_id_int)
    user = client.get(key)
    if not user:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Check if the user has an avatar
    if 'avatar' not in user:
        return jsonify({"Error": "Not found"}), 404

    # Delete the avatar from Google Cloud Storage
    storage_client = storage.Client()
    bucket_name = BUCKET_NAME  # Replace with your actual bucket name
    bucket = storage_client.bucket(bucket_name)
    blob_name = user['avatar']
    blob = bucket.blob(blob_name)

    # Attempt to delete the blob
    try:
        blob.delete()
    except Exception as e:
        return jsonify({"Error": "Failed to delete avatar"}), 500

    # Remove the 'avatar' field from the user entity
    del user['avatar']
    client.put(user)

    # Return success status with no body
    return '', 204

# Endpoint 7.
@app.route('/courses', methods=['POST'])
def create_course():
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user associated with the JWT
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Check if the user is an admin
    if jwt_user.get('role') != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the request content
    content = request.get_json()
    if not content:
        return jsonify({"Error": "The request body is invalid"}), 400

    required_attributes = ['subject', 'number', 'title', 'term', 'instructor_id']
    if any(attr not in content for attr in required_attributes):
        return jsonify({"Error": "The request body is invalid"}), 400

    # Validate instructor_id
    try:
        instructor_id_int = int(content['instructor_id'])
    except ValueError:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Check that instructor_id corresponds to an instructor
    instructor_key = client.key('users', instructor_id_int)
    instructor = client.get(instructor_key)
    if not instructor or instructor.get('role') != 'instructor':
        return jsonify({"Error": "The request body is invalid"}), 400

    # Create the course entity
    course_entity = datastore.Entity(key=client.key('courses'))
    course_entity.update({
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
        'instructor_id': instructor_id_int,
        'students': []
    })
    client.put(course_entity)

    # Construct the response
    response_body = {
        'id': course_entity.key.id,
        'subject': course_entity['subject'],
        'number': course_entity['number'],
        'title': course_entity['title'],
        'term': course_entity['term'],
        'instructor_id': course_entity['instructor_id'],
        'self': f"{BASE_URL}/courses/{course_entity.key.id}"
    }

    return jsonify(response_body), 201

# Endpoint 8.
@app.route('/courses', methods=['GET'])
def get_all_courses():
    # Get query parameters
    offset_param = request.args.get('offset')
    limit_param = request.args.get('limit')

    # Default values
    default_limit = 3
    default_offset = 0

    if offset_param is not None and limit_param is not None:
        # Use provided offset and limit
        offset = int(offset_param)
        limit = int(limit_param)
    else:
        # Use default offset and limit
        offset = default_offset
        limit = default_limit

    # The page size is always 3 as per instructions
    limit = 3

    # Query courses, ordered by 'subject'
    query = client.query(kind='courses')
    query.order = ['subject']

    # Fetch courses with offset and limit
    courses_iterator = query.fetch(offset=offset, limit=limit)
    courses_list = list(courses_iterator)

    # Build the courses array
    courses_array = []
    for course in courses_list:
        course_info = {
            'id': course.key.id,
            'subject': course.get('subject'),
            'number': course.get('number'),
            'title': course.get('title'),
            'term': course.get('term'),
            'instructor_id': course.get('instructor_id'),
            'self': f"{BASE_URL}/courses/{course.key.id}"
        }
        courses_array.append(course_info)

    # Build the response
    response_body = {
        'courses': courses_array
    }

    # Determine if there is a next page
    next_offset = offset + limit
    next_query = client.query(kind='courses')
    next_query.order = ['subject']
    next_courses_iterator = next_query.fetch(offset=next_offset, limit=1)
    next_courses_list = list(next_courses_iterator)

    if next_courses_list:
        # There is a next page
        next_url = f"{BASE_URL}/courses?limit={limit}&offset={next_offset}"
        response_body['next'] = next_url

    return jsonify(response_body), 200

# Endpoint 9.
@app.route('/courses/<course_id>', methods=['GET'])
def get_course(course_id):
    # Convert course_id to integer
    try:
        course_id_int = int(course_id)
    except ValueError:
        return jsonify({"Error": "Not found"}), 404

    # Retrieve the course from Datastore
    key = client.key('courses', course_id_int)
    course = client.get(key)
    if not course:
        return jsonify({"Error": "Not found"}), 404

    # Build the response without the list of enrolled students
    response_body = {
        'id': course.key.id,
        'subject': course.get('subject'),
        'number': course.get('number'),
        'title': course.get('title'),
        'term': course.get('term'),
        'instructor_id': course.get('instructor_id'),
        'self': f"{BASE_URL}/courses/{course.key.id}"
    }

    return jsonify(response_body), 200

# Endpoint 10.
@app.route('/courses/<course_id>', methods=['PATCH'])
def update_course(course_id):
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user associated with the JWT
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Check if the user is an admin
    if jwt_user.get('role') != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Convert course_id to integer
    try:
        course_id_int = int(course_id)
    except ValueError:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Retrieve the course from Datastore
    key = client.key('courses', course_id_int)
    course = client.get(key)
    if not course:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the request content
    content = request.get_json()
    if content is None:
        content = {}

    # If 'instructor_id' is in content, validate it
    if 'instructor_id' in content:
        try:
            instructor_id_int = int(content['instructor_id'])
        except ValueError:
            return jsonify({"Error": "The request body is invalid"}), 400

        # Check that instructor_id corresponds to an instructor
        instructor_key = client.key('users', instructor_id_int)
        instructor = client.get(instructor_key)
        if not instructor or instructor.get('role') != 'instructor':
            return jsonify({"Error": "The request body is invalid"}), 400

        # Update the instructor_id
        course['instructor_id'] = instructor_id_int

    # Update the course with other provided attributes
    allowed_attributes = ['subject', 'number', 'title', 'term']
    for attr in allowed_attributes:
        if attr in content:
            course[attr] = content[attr]

    # Save the updated course
    client.put(course)

    # Construct the response
    response_body = {
        'id': course.key.id,
        'subject': course.get('subject'),
        'number': course.get('number'),
        'title': course.get('title'),
        'term': course.get('term'),
        'instructor_id': course.get('instructor_id'),
        'self': f"{BASE_URL}/courses/{course.key.id}"
    }

    return jsonify(response_body), 200

# Endpoint 11.
@app.route('/courses/<course_id>', methods=['DELETE'])
def delete_course(course_id):
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user associated with the JWT
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Check if the user is an admin
    if jwt_user.get('role') != 'admin':
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Convert course_id to integer
    try:
        course_id_int = int(course_id)
    except ValueError:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Retrieve the course from Datastore
    key = client.key('courses', course_id_int)
    course = client.get(key)
    if not course:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Remove the course from each student's 'courses' list
    student_ids = course.get('students', [])
    for student_id in student_ids:
        student_key = client.key('users', student_id)
        student = client.get(student_key)
        if student and student.get('role') == 'student':
            if 'courses' in student and course_id_int in student['courses']:
                student['courses'].remove(course_id_int)
                client.put(student)

    # Since the instructor is no longer associated with the course,
    # but we don't need to update the instructor entity because
    # we fetch instructor's courses by querying 'courses' with 'instructor_id'

    # Delete the course entity
    client.delete(key)

    # Return 204 No Content
    return '', 204

# Endpoint 12.
@app.route('/courses/<course_id>/students', methods=['PATCH'])
def update_course_enrollment(course_id):
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user associated with the JWT
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Convert course_id to integer
    try:
        course_id_int = int(course_id)
    except ValueError:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Retrieve the course from Datastore
    key = client.key('courses', course_id_int)
    course = client.get(key)
    if not course:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Check if user is admin or instructor of the course
    is_admin = jwt_user.get('role') == 'admin'
    is_instructor = jwt_user.get('role') == 'instructor' and jwt_user.key.id == course.get('instructor_id')
    if not (is_admin or is_instructor):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the request content
    content = request.get_json()
    if not content or 'add' not in content or 'remove' not in content:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Check that at least one of 'add' or 'remove' is non-empty
    if not content['add'] and not content['remove']:
        return jsonify({"Error": "The request body is invalid"}), 400

    # Convert 'add' and 'remove' to sets and check for integers
    try:
        add_set = set(content['add'])
        remove_set = set(content['remove'])
    except ValueError:
        return jsonify({"Error": "Enrollment data is invalid"}), 409

    # Ensure elements are integers
    if not all(isinstance(id, int) for id in add_set | remove_set):
        return jsonify({"Error": "Enrollment data is invalid"}), 409

    # Check for common values between 'add' and 'remove'
    if add_set & remove_set:
        return jsonify({"Error": "Enrollment data is invalid"}), 409

    # Verify all IDs correspond to students
    student_ids = add_set | remove_set
    for student_id in student_ids:
        student_key = client.key('users', student_id)
        student = client.get(student_key)
        if not student or student.get('role') != 'student':
            return jsonify({"Error": "Enrollment data is invalid"}), 409

    # Update course enrollment
    enrolled_students = set(course.get('students', []))

    # Add students (skip if already enrolled)
    enrolled_students.update(add_set)

    # Remove students (skip if not enrolled)
    enrolled_students.difference_update(remove_set)

    # Update the course entity
    course['students'] = list(enrolled_students)
    client.put(course)

    # Update each student's 'courses' property
    for student_id in add_set:
        student_key = client.key('users', student_id)
        student = client.get(student_key)
        if 'courses' not in student:
            student['courses'] = []
        if course_id_int not in student['courses']:
            student['courses'].append(course_id_int)
            client.put(student)

    for student_id in remove_set:
        student_key = client.key('users', student_id)
        student = client.get(student_key)
        if 'courses' in student and course_id_int in student['courses']:
            student['courses'].remove(course_id_int)
            client.put(student)

    # Return success with empty body
    return '', 200

# Endpoint 13.
@app.route('/courses/<course_id>/students', methods=['GET'])
def get_course_enrollment(course_id):
    # Verify the JWT
    try:
        payload = verify_jwt(request)
        jwt_sub = payload['sub']
    except:
        return jsonify({"Error": "Unauthorized"}), 401

    # Get the user associated with the JWT
    query = client.query(kind='users')
    query.add_filter('sub', '=', jwt_sub)
    jwt_user_results = list(query.fetch())
    if not jwt_user_results:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    jwt_user = jwt_user_results[0]

    # Convert course_id to integer
    try:
        course_id_int = int(course_id)
    except ValueError:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Retrieve the course from Datastore
    key = client.key('courses', course_id_int)
    course = client.get(key)
    if not course:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Check if user is admin or instructor of the course
    is_admin = jwt_user.get('role') == 'admin'
    is_instructor = (
        jwt_user.get('role') == 'instructor' and jwt_user.key.id == course.get('instructor_id')
    )
    if not (is_admin or is_instructor):
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    # Get the list of students enrolled in the course
    student_ids = course.get('students', [])

    # Return the list as JSON array
    return jsonify(student_ids), 200

# Test + Utilities.

# Test if the app is running on the correct location.
@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"

# Test. --------------------------------------------------------------------
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
# Test. --------------------------------------------------------------------

# Run the code.
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
    