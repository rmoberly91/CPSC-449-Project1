from flask import Flask, rquest, jsonify, session, make_response
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insert_your_secret_key_here'
app.config['JWT_SECRET_KEY'] = 'insert_your_jwt_secret_key_here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)

jwt = JWTManager(app)

users = []
inventory = []

@app.route('/register', methods=['POST'])
def register():
    data = request.json()
    #we need a way to encrypt the password before storing it
    new_user = {
        'username': data['username'],
        'password': data['password'], #hash the password first
        'email': data['email'],
        'is_admin': data.get('is_admin', False)
    }
    users.append(new_user)
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json()
    username = data['username']
    password = data['password']

    user = next((u for u in users if u['username'] == username and u['password'] == password), None)
    if user:
        access_token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']}, app.config['JWT_SECRET_KEY'])
        refresh_token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']}, app.config['JWT_SECRET_KEY'])
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    # Invalidate the tokens (this is a placeholder, implement your own logic)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/inventory', methods=['POST'])
@jwt_required()
def create_inventory():
    data = request.json()
    new_item = {
        'name': data['name'],
        'quantity': data['quantity'],
        'price': data['price'],
        'description': data['description'],
        'id': len(inventory) + 1
    }
    inventory.append(new_item)
    return jsonify({'message': 'Item added to inventory'}), 201