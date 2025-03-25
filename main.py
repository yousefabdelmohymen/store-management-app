from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import pyotp
import qrcode
import io
import datetime

# ----------------------- App Configuration -----------------------

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///StoreDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # In production, use environment variables

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# ----------------------- Database Models -----------------------

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    secret = db.Column(db.String(32), nullable=True)  # 2FA secret

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'username': self.username}


class Product(db.Model):
    __tablename__ = 'products'
    pid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pname = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'pid': self.pid,
            'pname': self.pname,
            'description': self.description,
            'price': str(self.price),
            'stock': self.stock,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


with app.app_context():
    db.create_all()


# ----------------------- Helper Functions -----------------------

def get_required_data(data, required_fields):
    """Helper to validate that required fields exist in the provided data."""
    missing = [field for field in required_fields if field not in data]
    if missing:
        return False, f"Missing fields: {', '.join(missing)}"
    return True, None


# ----------------------- Authentication Routes -----------------------

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    valid, error_msg = get_required_data(data, ['name', 'username', 'password'])
    if not valid:
        return jsonify({'error': error_msg}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    secret = pyotp.random_base32()
    new_user = User(
        name=data['name'],
        username=data['username'],
        password=hashed_password,
        secret=secret
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully, please set up 2FA'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    valid, error_msg = get_required_data(data, ['username', 'password'])
    if not valid:
        return jsonify({'error': error_msg}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({'message': 'Enter 2FA code', 'username': user.username}), 200


@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    username = data.get('username')
    user_code = data.get('code')
    
    if not username or not user_code:
        return jsonify({'error': 'Username and 2FA code are required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    totp = pyotp.TOTP(user.secret)
    if totp.verify(user_code):
        token = create_access_token(
            identity=str(user.id),
            expires_delta=datetime.timedelta(minutes=10)
        )
        return jsonify({'message': '2FA verified successfully', 'token': token})
    else:
        return jsonify({'error': 'Invalid or expired code'}), 401


@app.route('/generate-2fa/<username>', methods=['GET'])
def generate_2fa(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    totp = pyotp.TOTP(user.secret)
    uri = totp.provisioning_uri(name=username, issuer_name='Data_Integrity_Section_2FA')
    qr = qrcode.make(uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')


# ----------------------- Product Operations -----------------------

@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.get_json()
    valid, error_msg = get_required_data(data, ['pname', 'price', 'stock'])
    if not valid:
        return jsonify({'error': error_msg}), 400

    new_product = Product(
        pname=data['pname'],
        description=data.get('description', ''),
        price=data['price'],
        stock=data['stock']
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify(new_product.to_dict()), 201


@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    products = Product.query.all()
    return jsonify([product.to_dict() for product in products])


@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify(product.to_dict())


@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.get_json()
    product.pname = data.get('pname', product.pname)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.stock = data.get('stock', product.stock)

    db.session.commit()
    return jsonify(product.to_dict())


@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'}), 200


# ----------------------- Application Entry Point -----------------------

if __name__ == '__main__':
    app.run(debug=True)
