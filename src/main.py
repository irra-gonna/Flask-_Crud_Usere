
from flask import Flask, request, jsonify, Response
from flask_pymongo import PyMongo
from bson import json_util
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from bson.objectid import ObjectId


app = Flask(__name__)
#Mongodb database connection
app.config['MONGO_URI'] = 'mongodb://localhost:27017/crudflask'
mongo = PyMongo(app)

#Jwt 
app.config["JWT_SECRET_KEY"] = "this-is-secret-key"
jwt = JWTManager(app)


@app.route("/")
@jwt_required()
def index():
    
    return jsonify(message="Welcome! to crudflask")


#API routes
@app.route('/users/<id>', methods = ['GET'])
def get_user(id):
    user = mongo.db.users.find_one({'_id': ObjectId(id)})
    response = json_util.dumps(user)
    return Response(response, mimetype = 'application/json')

@app.route('/users', methods = ['GET'])
def get_users():
    users = mongo.db.users.find()
    response = json_util.dumps(users)
    return Response(response, mimetype='application/json') 


@app.route('/register', methods = ["POST"])
def register():
    email = request.json['email']
    test = mongo.db.users.find_one({'email': email})
    if test:
        return jsonify({'message': 'User with email ' + email +  ' already exist'})
    else:
        username = request.json['username']
        email = request.json['email']
        password = request.json['password']

    if username and email and password:
        hashed_password = generate_password_hash(password)
        id = mongo.db.users.insert_one(
            {
            'username': username,
            'email': email,
            'password': hashed_password,
            }
        )
        response = {
            'id': str(id),
            'username': username,
            'email': email,
            'password': hashed_password
        }
        return response
        
    else:
            
        return not_found()


@app.errorhandler(404)
def not_found(error=None):
    response = jsonify({
        'message': ' Not found ' + request.url,
        'status': 404
    })
    response.status_code = 404
    return response

@app.route("/login", methods=["POST"])
def login():
    if request.is_json:
        email = request.json["email"]
        password = request.json["password"]
    else:
        email = request.form["email"]
        password = request.form["password"]

    test = mongo.db.users.find_one({"email": email,"password":password})
    if test:
        access_token = create_access_token(identity=email)
        return jsonify(message="Login Succeeded!", access_token=access_token), 201
    else:
        return jsonify(message="Bad Email or Password"), 401


@app.route('/users/<id>', methods = ['PATCH'])
def update_user(id):
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    if username and email and password:
        hashed_password = generate_password_hash(password)
        mongo.db.users.update_one({'_id': ObjectId(id)}, {'$set': {
            'username': username,
            'email': email,
            'password': hashed_password
        }})
        response = jsonify({'message': 'User ' + id + ' was susseccfully updated'})
        return response


@app.route('/users/<id>', methods = ['DELETE'])
def delete_user(id):
    mongo.db.users.delete_one({'_id': ObjectId(id)})
    response = jsonify({'message': 'User ' + id + ' was susseccfully deleted'})
    return response


if __name__ == '__main__':
    app.run(debug=True, port=5000)
