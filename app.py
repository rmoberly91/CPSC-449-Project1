from flask import Flask, request, jsonify, session, make_response
import jwt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insert_your_secret_key_here'
app.config['JWT_SECRET_KEY'] = 'insert_your_jwt_secret_key_here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
app.config['SESSION_COOKIE_NAME'] = 'bakery_app_session'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False


jwt = JWTManager(app)

users = [
    {'username': 'Adam', 'password': generate_password_hash('Apple123'), 'email': 'adam123@mail.com', 'is_admin': True}
]
#needs auto creation of ID
inventory = [
    {'name': 'cookie', 'description': 'chocolate chip cookie', 'quantity': 15, 'price': 2.50, 'id': 1, 'owner': 'Adam'},
    {'name': 'cake', 'description': 'chantilly cake round', 'quantity': 5, 'price': 20.00, 'id': 2, 'owner': 'Adam'},
    {'name': 'donut', 'description': 'jelly-filled donut', 'quantity': 40, 'price': 2.00, 'id': 3, 'owner': 'Adam'},
    {'name': 'pie', 'description': 'apple pie', 'quantity': 10, 'price': 12.00, 'id': 4, 'owner': 'Adam'},
    {'name': 'pan dulce', 'description': 'chocolate concha', 'quantity': 20, 'price': 3.00, 'id': 5, 'owner': 'Adam'},
    {'name': 'bread', 'description': 'focaccia bread', 'quantity': 6, 'price': 12.00, 'id': 6, 'owner': 'Adam'}, 
    {'name': '', 'description': '', 'quantity': 0, 'price': 0.00, 'id': 0, 'owner': 'admin'}, # Placeholder for new items
]

@app.route('/register', methods=['POST'])
def register():
    # check that user and pass were entered
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Username and password are required'}), 400
    
    data = request.get_json()

    # registration validation
    if not isinstance(data['username'], str):
        return jsonify({'error': 'Username must be a string'}), 400
    if len(data['password']) < 8 or not re.search(r"[A-Z]", data['password']) or not re.search(r"[0-9]", data['password']):
        return jsonify({'error': 'Password must be at least 8 characters long, containing at least one uppercase letter and at least one number'}), 400
    if not re.match(r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", data['email']):
        return jsonify({'error': 'Email must be valid'}), 400
    if data['username'] in users or data['email'] in users:
        return jsonify({'error': 'User already exists'}), 400
    
    #we need a way to encrypt the password before storing it
    new_user = {
        'username': data['username'],
        'password': generate_password_hash(data['password']), #hash the password first
        'email': data['email'],
        'is_admin': data.get('is_admin', False)
    }
    users.append(new_user)
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required'}), 400
    
    username = data['username']
    password = data['password']
    
    user = next((u for u in users if u['username'] == username), None)
    if user and check_password_hash(user['password'], password):
        session['user'] = username
        session.permanent = True
        
        response = make_response(jsonify({'message': 'Login successful'}))
        response.set_cookie('username', username, httponly = True, 
                            secure = True, max_age = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()) 
        
        access_token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']}, app.config['JWT_SECRET_KEY'])
        refresh_token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']}, app.config['JWT_SECRET_KEY'])
        
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200 
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.set_cookie('username', '', expires=0)
    # Invalidate the tokens (this is a placeholder, implement your own logic)
    return response, 200

@app.route('/inventory', methods=['POST'])
@jwt_required()
def create_inventory():
    data = request.get_json()

    # item validation
    if not isinstance(data['name'], str):
        return jsonify({'error': 'Name must be a string'}, 400)
    if not isinstance(data['description'], str):
        return jsonify({'error': 'Description must be a string'}, 400)
    if not isinstance(data['quantity'], int):
        return jsonify({'error': 'Quantity must be an integer'}, 400)
    if not re.match(r"^[1-9][0-9]+\.[0-9]{2}$", data['price']):
        return jsonify({'error': 'Price must be in US currency format'}, 400)
    if not isinstance(data['id'], int):
        return jsonify({'error': 'ID must be an integer'}, 400)
    if data['name'] in inventory or data['id'] in inventory:
        return jsonify('error': 'Item already exists')

    new_item = {
        'name': data['name'],
        'description': data['description'],
        'quantity': data['quantity'],
        'price': data['price'],
        'id': len(inventory) + 1,
        'owner': get_jwt_identity()
    }
    inventory.append(new_item)
    return jsonify({'message': 'Item added to inventory'}), 201

@app.route('/inventory', methods=['GET'])
@jwt_required()
def get_inventory():
    user = get_jwt_identity()
    user_inventory = [item for item in inventory if item.get('owner') == user]
    return jsonify(user_inventory), 200

@app.route('/inventory/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_inventory(item_id):
    user = get_jwt_identity()
    data = request.get_json()
    item = next((item for item in inventory if item['id'] == item_id), None)
    
    if not item:
        return jsonify({'message': 'Item not found'}), 404

    if item.get('owner') != user:
        return jsonify({'message': 'Unauthorized'}), 403

    item.update(data)
    return jsonify({'message': 'Item updated successfully'}), 200

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_inventory(item_id):
    global inventory
    user = get_jwt_identity()
    item = next((item for item in inventory if item['id'] == item_id), None)

    if not item:
        return jsonify({'message': 'Item not found'}), 404

    if item.get('owner') != user:
        return jsonify({'message': 'Unauthorized'}), 403

    inventory = [item for item in inventory if item['id'] != item_id]
    return jsonify({'message': 'Item deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)