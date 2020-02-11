from flask import Flask, render_template, request, redirect, session, flash, json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import requests
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "QaWsEdRfTgYh12345!!"

bcrypt = Bcrypt(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

add_to_cart_table = db.Table('cart', 
    db.Column('item_id', db.Integer, db.ForeignKey('items.id', ondelete="cascade"), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete="cascade"), primary_key=True)
)

class User(db.Model):	
    __tablename__ = "users"    		
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(45))
    email = db.Column(db.String(45), unique=True)
    password = db.Column(db.String(255))
    address_line1 = db.Column(db.String(255))
    address_line2 = db.Column(db.String(255))
    city = db.Column(db.String(255))
    state = db.Column(db.String(45))
    zip = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, server_default=func.now())  
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    cart_added = db.relationship("Item", secondary = add_to_cart_table)

    def __repr__(self):
        return f"<User: {self.first_name}>"

class Item(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    info = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="cascade"), nullable=False)
    user = db.relationship("User", foreign_keys=[user_id], backref="items")
    created_at = db.Column(db.DateTime, server_default=func.now())   
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/sign_up')
def sign_up():
    return render_template("signup.html")

@app.route('/new_user', methods=['POST'])
def new_user():
    errors = []

    if not EMAIL_REGEX.match(request.form['email']):
        errors.append("Your email address is invalid. Please try again.")
        valid = False

    if len(request.form['password']) < 8:
        errors.append("Your password must be at least 8 characters long.")
        valid = False

    if len(request.form['full_name']) < 2:
        errors.append("Your name must be at least 2 characters long.")
        valid = False

    user_check = User.query.filter_by(email=request.form["email"]).first() 
    if user_check is not None:
        errors.append("Your email is already in use. Please log in.")

    if errors:
        for e in errors:
            flash(e)
    else:
        hashed = bcrypt.generate_password_hash(request.form["password"])
        new_user = None

        new_user = User(
            full_name = request.form["full_name"],
            email = request.form["email"],
            password = hashed
        )
        
        db.session.add(new_user)
        db.session.commit()
        session["user_id"] = new_user.id
        return redirect('/')

    return redirect('/login')

@app.route('/user/login', methods=['POST'])
def user_login():
    errors = []

    user_attempt = User.query.filter_by(email=request.form["email"]).first()
    
    if not user_attempt:
        flash("Your email and password combination is incorrect.")
        return redirect("/sign_up")

    if not bcrypt.check_password_hash(user_attempt.password, request.form["password"]):
        flash("Your email and password combination is incorrect.")
        return redirect("/sign_up")

    session["user_id"] = user_attempt.id
    return redirect('/')

@app.route('/women')
def women():
    return render_template("shoppingcartWomen.html")

@app.route('/women/checkout', methods=['POST'])
def women_checkout():
    print("Get Post Info")
    print(request.form)
    sweater1_from_form = request.form['sweater1']
    #insert remaining clothing items here 

@app.route('/men')
def men():
    return render_template("shoppingcartMen.html")

@app.route('/men/checkout', methods=['POST'])
def men_checkout():
    print("Get Post Info")
    print(request.form)
    sweater1_from_form = request.form['sweater1']
    #insert remaining clothing items here 

@app.route('/cart/<user_id>')
def cart(user_id):
    user = User.query.get(user_id)
    return render_template("cart.html", user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)