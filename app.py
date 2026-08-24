import os
import secrets
from datetime import datetime, timedelta

import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*"
        }
    }
)

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///asap.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

JWT_SECRET = os.getenv("JWT_SECRET")

if not JWT_SECRET:
    JWT_SECRET = "development-only-change-this-secret"

db = SQLAlchemy(app)


# =========================
# DATABASE MODELS
# =========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(180), unique=True, nullable=False)
    phone = db.Column(db.String(30), unique=True, nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(
        db.String(30),
        default="customer",
        nullable=False
    )

    referral_code = db.Column(
        db.String(40),
        unique=True,
        nullable=False
    )

    referred_by = db.Column(
        db.String(40),
        nullable=True
    )

    referral_balance = db.Column(
        db.Integer,
        default=0,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Seller(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    business_name = db.Column(
        db.String(180),
        nullable=False
    )

    phone = db.Column(
        db.String(30),
        nullable=False
    )

    category = db.Column(
        db.String(100),
        default="Fabric & Aso Ebi"
    )

    status = db.Column(
        db.String(30),
        default="pending"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    seller_id = db.Column(
        db.Integer,
        db.ForeignKey("seller.id"),
        nullable=False
    )

    name = db.Column(
        db.String(200),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=True
    )

    category = db.Column(
        db.String(100),
        nullable=False
    )

    price = db.Column(
        db.Integer,
        nullable=False
    )

    unit = db.Column(
        db.String(30),
        default="piece"
    )

    stock = db.Column(
        db.Integer,
        default=0
    )

    image_url = db.Column(
        db.String(500),
        nullable=True
    )

    status = db.Column(
        db.String(30),
        default="pending"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    total = db.Column(
        db.Integer,
        nullable=False
    )

    status = db.Column(
        db.String(40),
        default="pending"
    )

    payment_status = db.Column(
        db.String(40),
        default="unpaid"
    )

    reference = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    referrer_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    referred_user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    reward = db.Column(
        db.Integer,
        default=0
    )

    status = db.Column(
        db.String(30),
        default="pending"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# =========================
# HELPERS
# =========================

def create_token(user):
    payload = {
        "user_id": user.id,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(days=7)
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


def get_current_user():

    header = request.headers.get("Authorization")

    if not header:
        return None

    if not header.startswith("Bearer "):
        return None

    token = header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        return db.session.get(
            User,
            payload["user_id"]
        )

    except Exception:
        return None


def generate_referral_code():

    while True:

        code = "ASAP-" + secrets.token_hex(4).upper()

        exists = User.query.filter_by(
            referral_code=code
        ).first()

        if not exists:
            return code


# =========================
# HEALTH CHECK
# =========================

@app.get("/")
def home():

    return jsonify({
        "success": True,
        "name": "ASAP Marketplace API",
        "version": "1.0.0",
        "status": "online"
    })


@app.get("/api/health")
def health():

    return jsonify({
        "success": True,
        "status": "healthy"
    })


# =========================
# AUTH
# =========================

@app.post("/api/auth/register")
def register():

    data = request.get_json() or {}

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()
    password = data.get("password", "")
    referral_code = data.get(
        "referral_code",
        ""
    ).strip().upper()

    if not name or not email or not password:

        return jsonify({
            "success": False,
            "message": "Name, email and password are required."
        }), 400

    existing = User.query.filter_by(
        email=email
    ).first()

    if existing:

        return jsonify({
            "success": False,
            "message": "An account with this email already exists."
        }), 409

    referred_by = None
    referrer = None

    if referral_code:

        referrer = User.query.filter_by(
            referral_code=referral_code
        ).first()

        if not referrer:

            return jsonify({
                "success": False,
                "message": "Invalid referral code."
            }), 400

        referred_by = referral_code

    user = User(
        name=name,
        email=email,
        phone=phone or None,
        password_hash=generate_password_hash(password),
        referral_code=generate_referral_code(),
        referred_by=referred_by
    )

    db.session.add(user)
    db.session.commit()

    if referrer and referrer.id != user.id:

        referral = Referral(
            referrer_id=referrer.id,
            referred_user_id=user.id
        )

        db.session.add(referral)
        db.session.commit()

    token = create_token(user)

    return jsonify({
        "success": True,
        "message": "Account created successfully.",
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "referral_code": user.referral_code,
            "role": user.role
        }
    }), 201


@app.post("/api/auth/login")
def login():

    data = request.get_json() or {}

    identity = data.get(
        "identity",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    user = User.query.filter(
        db.or_(
            User.email == identity,
            User.phone == identity
        )
    ).first()

    if not user or not check_password_hash(
        user.password_hash,
        password
    ):

        return jsonify({
            "success": False,
            "message": "Invalid login details."
        }), 401

    token = create_token(user)

    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "referral_code": user.referral_code,
            "referral_balance": user.referral_balance
        }
    })


@app.get("/api/auth/me")
def me():

    user = get_current_user()

    if not user:

        return jsonify({
            "success": False,
            "message": "Unauthorized."
        }), 401

    return jsonify({
        "success": True,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "referral_code": user.referral_code,
            "referral_balance": user.referral_balance
        }
    })


# =========================
# PRODUCTS
# =========================

@app.get("/api/products")
def products():

    category = request.args.get("category")

    query = Product.query.filter_by(
        status="approved"
    )

    if category:
        query = query.filter_by(
            category=category
        )

    items = query.order_by(
        Product.created_at.desc()
    ).all()

    return jsonify({
        "success": True,
        "products": [
            {
                "id": item.id,
                "name": item.name,
                "description": item.description,
                "category": item.category,
                "price": item.price,
                "unit": item.unit,
                "stock": item.stock,
                "image_url": item.image_url
            }
            for item in items
        ]
    })


# =========================
# SELLER
# =========================

@app.post("/api/sellers")
def create_seller():

    user = get_current_user()

    if not user:

        return jsonify({
            "success": False,
            "message": "Login required."
        }), 401

    data = request.get_json() or {}

    business_name = data.get(
        "business_name",
        ""
    ).strip()

    phone = data.get(
        "phone",
        ""
    ).strip()

    category = data.get(
        "category",
        "Fabric & Aso Ebi"
    )

    if not business_name or not phone:

        return jsonify({
            "success": False,
            "message": "Business name and phone are required."
        }), 400

    seller = Seller(
        user_id=user.id,
        business_name=business_name,
        phone=phone,
        category=category
    )

    db.session.add(seller)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Seller application submitted.",
        "seller_id": seller.id,
        "status": seller.status
    }), 201


# =========================
# REFERRALS
# =========================

@app.get("/api/referrals")
def referrals():

    user = get_current_user()

    if not user:

        return jsonify({
            "success": False,
            "message": "Login required."
        }), 401

    records = Referral.query.filter_by(
        referrer_id=user.id
    ).order_by(
        Referral.created_at.desc()
    ).all()

    return jsonify({
        "success": True,
        "referral_code": user.referral_code,
        "balance": user.referral_balance,
        "total_referrals": len(records),
        "referrals": [
            {
                "id": r.id,
                "status": r.status,
                "reward": r.reward,
                "created_at": r.created_at.isoformat()
            }
            for r in records
        ]
    })


# =========================
# DATABASE INITIALIZATION
# =========================

with app.app_context():
    db.create_all()


# =========================
# RUN
# =========================

if __name__ == "__main__":

    port = int(
        os.getenv("PORT", "5000")
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
