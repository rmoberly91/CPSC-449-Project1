from flask import Flask, request, jsonify, session, make_response
import jwt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token, get_jwt, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import re
import logging  
from functools import wraps
import os
from dotenv import load_dotenv
from werkzeug.exceptions import HTTPException
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SECRET_KEY'] = 'insert_your_secret_key_here'
app.config['JWT_SECRET_KEY'] = 'insert_your_jwt_secret_key_here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)
app.config['SESSION_COOKIE_NAME'] = 'bakery_app_session'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['SQLACHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # Example URI for SQLite

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    #owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('inventory', lazy=True))

def session_jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'No active session. Please log in.'}), 401
            
        # Check if session has expired
        session_start_time = session.get('start_time')
        if session_start_time:
            if isinstance(session_start_time, str):
                try:
                    session_start_time = datetime.datetime.fromisoformat(session_start_time.replace('Z', '+00:00'))
                except ValueError:
                    session_start_time = datetime.datetime.strptime(session_start_time, '%Y-%m-%d %H:%M:%S.%f')
                session_start_time = session_start_time.replace(tzinfo=datetime.timezone.utc)
            
            session_age = datetime.datetime.now(datetime.timezone.utc) - session_start_time
            if session_age > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                return jsonify({'message': 'Session expired. Please log in again.'}), 401
        
        verify_jwt_in_request()
        if get_jwt_identity() != session.get('user'):
            return jsonify({'error': 'Session invalid.'}), 401
            
        return fn(*args, **kwargs)
    return wrapper


jwt = JWTManager(app)
jwt_blacklist = set()

'''
users = [
    # {'username': 'Adam', 'password': generate_password_hash('Apple123'), 'email': 'adam123@mail.com', 'is_admin': True}
]
#needs auto creation of ID
inventory = [
    # {'name': 'cookie', 'description': 'chocolate chip cookie', 'quantity': 15, 'price': 2.50, 'id': 1, 'owner': 'Adam'},
    # {'name': 'cake', 'description': 'chantilly cake round', 'quantity': 5, 'price': 20.00, 'id': 2, 'owner': 'Adam'},
    # {'name': 'donut', 'description': 'jelly-filled donut', 'quantity': 40, 'price': 2.00, 'id': 3, 'owner': 'Adam'},
    # {'name': 'pie', 'description': 'apple pie', 'quantity': 10, 'price': 12.00, 'id': 4, 'owner': 'Adam'},
    # {'name': 'pan dulce', 'description': 'chocolate concha', 'quantity': 20, 'price': 3.00, 'id': 5, 'owner': 'Adam'},
    # {'name': 'bread', 'description': 'focaccia bread', 'quantity': 6, 'price': 12.00, 'id': 6, 'owner': 'Adam'}, 
    #{'name': '', 'description': '', 'quantity': 0, 'price': 0.00, 'id': 0, 'owner': 'admin'}, # Placeholder for new items
]
'''

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in jwt_blacklist 

@app.errorhandler(400)
def bad_request(e):
    return jsonify(error = str(e)), 400

@app.errorhandler(401)
def unauthenticated(e):
    return jsonify(error = str(e)), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify(error = str(e)), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify(error = str(e)), 404

@app.errorhandler(406)
def not_acceptable(e):
    return jsonify(error = str(e)), 406

@app.errorhandler(415)
def unsupported_media_type(e):
    return jsonify(error = str(e)), 415

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify(error = str(e)), 429

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        response = e.get_response()
        response.data = jsonify({'error': e.description})
        response.content_type = 'application/json'
        return response
    
    app.logger.error(f'Unhandled Exception: %s', str(e), exc_info=True)
    return jsonify({'error': 'Internal Server Error'}), 500
    


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
    if any(u['username'] == data['username'] for u in users) or any(u['email'] == data['email'] for u in users):
        return jsonify({'error': 'User already exists'}), 400
    
    #we need a way to encrypt the password before storing it
    new_user = {
        'username': data['username'],
        'password': generate_password_hash(data['password']), #hash the password first
        'email': data['email'],
        'is_admin': data.get('is_admin', False)
    }
    #users.append(new_user)
    db.session.add(new_user)
    
    return jsonify({'message': 'User registered successfully'}), 201 # *Admin

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    if not username:
        return jsonify({'message': 'Invalid credentials'}), 401
    password = data['password']
    
    if user and check_password_hash(user.password, password):
        
        current_time = datetime.datetime.now(datetime.timezone.utc)
        
        session['user'] = user.username
        session['start_time'] = current_time.isoformat()
        
        # Generate tokens
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        
        response = make_response(jsonify({'message': 'Login successful', 'access_token': access_token, 'refresh_token': refresh_token
        }))
        
        # Set session cookie
        response.set_cookie('username', username, httponly=True, secure=True, max_age=app.config['PERMANENT_SESSION_LIFETIME'].total_seconds())
        
        return response, 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@session_jwt_required
def logout():
    jti = get_jwt()['jti']
    jwt_blacklist.add(jti)
    session.pop('user', None)
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.set_cookie('username', '', expires=0)
    response.set_cookie(app.config['SESSION_COOKIE_NAME'], '', httponly=True, secure=True, expires=0)
    return response, 200


@app.route('/inventory', methods=['POST'])
@session_jwt_required
def create_inventory():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No input data provided'}), 400

    # Type checks
    if not isinstance(data['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if not isinstance(data['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if not isinstance(data['quantity'], int):
        return jsonify({'error': 'Quantity must be an integer'}), 400
    if data['quantity'] < 0: 
        return jsonify({'error': 'Quantity can not be negative'}), 400
    if not isinstance(data['price'], (int, float)):
        return jsonify({'error': 'Price must be a number'}), 400
    if data['price'] < 0: 
        return jsonify({'error': 'Price can not be negative'}), 400
    if isinstance(data['price'], float) and not re.match(r"^\d+(\.\d{1,2})?$", f"{data['price']:.2f}"):
        return jsonify({'error': 'Price must be in US currency format (e.g., 12.34)'}), 400
    if any(item['name'].lower() == data['name'].lower() for item in inventory):
        return jsonify({'error': 'Item already exists'}), 400

    # Create item
    new_item = {
        'name': data['name'],
        'description': data['description'],
        'quantity': data['quantity'],
        'price': data['price'],
        'id': max((item['id'] for item in inventory), default=0) + 1,
        'owner': get_jwt_identity()
    }
    
    db.session.add(new_item)
    db.session.commit()
    
    return jsonify({'message': 'Item added to inventory'}), 201


@app.route('/inventory', methods=['GET'])
@session_jwt_required
def get_inventory():
    items = Inventory.query.all()
    current_inventory = []
    for item in items:
        current_inventory.append({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'quantity': item.quantity,
            'price': item.price,
            'owner': item.owner.username
        })
    return jsonify(user_inventory), 200


@app.route('/inventory/<int:item_id>', methods=['PUT'])
@session_jwt_required
def update_inventory(item_id):
    user = get_jwt_identity()
    data = request.get_json()

    item = Inventory.query.filter_by(id=item_id).first()

    # Borrowed from create_inventory function
    if not isinstance(data['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if not isinstance(data['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if not isinstance(data['quantity'], int):
        return jsonify({'error': 'Quantity must be an integer'}), 400
    if data['quantity'] < 0:
        return jsonify({'error': 'Quantity can not be negative'}), 400
    if not isinstance(data['price'], (int, float)):
        return jsonify({'error': 'Price must be a number'}), 400
    if data['price'] < 0: 
        return jsonify({'error': 'Price can not be negative'}), 400
    if isinstance(data['price'], float) and not re.match(r"^\d+(\.\d{1,2})?$", f"{data['price']:.2f}"):
        return jsonify({'error': 'Price must be in US currency format (e.g., 12.34)'}), 400
    if item.get('owner') != user:
        return jsonify({'message': 'Unauthorized'}), 403
    
    if item and item.get('owner') == user:
       item.name = data.get('name', item.name)
       item.description = data.get('description', item.description)         
       item.quantity = data.get('quantity', item.quantity)
       item.price = data.get('price', item.price)
       db.session.commit() 
       return jsonify({'message': 'Item updated successfully'}), 200



@app.route('/inventory/<int:item_id>', methods=['GET'])
@session_jwt_required
def get_single_inventory(item_id):
    global inventor
    user = get_jwt_identity()
    item = next((item for item in inventory if item['id'] == item_id), None)

    if not item:
        return jsonify({'message': 'Item not found'}), 404

    if item.get('owner') != user:
        return jsonify({'message': 'Unauthorized'}), 403

    return jsonify(item), 200

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
@session_jwt_required
def delete_inventory(item_id):
    global inventory
    user = get_jwt_identity()
    item = Inventory.query.filter_by(id=item_id).first()

    if not item:
        return jsonify({'message': 'Item not found'}), 404

    if item.get('owner') != user:
        return jsonify({'message': 'Unauthorized'}), 403

    db.session.delete(item)
    db.session.commit()
    return jsonify({'message': 'Item deleted successfully'}), 200


@app.route('/admin/inventory', methods=['GET'])
@session_jwt_required
def get_all_inventory_admin():
    username = get_jwt_identity()
    user = next((u for u in users if u['username'] == username), None)

    if not user or not user.get('is_admin'):
        return jsonify({'message': 'Unauthorized: Admin access required'}), 403
    if not inventory:
        return jsonify({'message': 'No items in inventory'}), 404

    return jsonify(inventory), 200


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)  
def refresh():
    identity = get_jwt_identity()
    new_token = create_access_token(identity=identity)
    
    # Update session start time when refreshing token
    if 'user' in session and session['user'] == identity:
        session['start_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    return jsonify({'access_token': new_token}), 200

if __name__ == '__main__':
    app.run(debug=True)