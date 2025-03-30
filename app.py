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
        'id': len(inventory) + 1,
        'owner': get_jwt_identity()
    }
    inventory.append(new_item)
    return jsonify({'message': 'Item added to inventory'}), 201

@app.route('/inventory', methods=['GET'])
@jwt_required()
def get_inventory():
    user = get_jwt_identity()
    user_inventory = [item for item in inventory if item['owner'] == user]
    return jsonify(user_inventory), 200

@app.route('/inventory/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_inventory(item_id):
    data = request.json()
    item = next((item for item in inventory if item['id'] == item_id), None)
    if item:
        item.update(data)
        return jsonify({'message': 'Item updated successfully'}), 200
    return jsonify({'message': 'Item not found'}), 404

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_inventory(item_id):
    global inventory
    inventory = [item for item in inventory if item['id'] != item_id]
    return jsonify({'message': 'Item deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)