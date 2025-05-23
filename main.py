import os
from flask import Flask, render_template, request, session, redirect, url_for, flash
import random
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from random import randint
from dotenv import load_dotenv
from flask_migrate import Migrate
import re
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("Error: DATABASE_URL is not set. Check your .env file!")

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace("postgresql", "postgresql+psycopg2")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp = db.Column(db.String(6), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)


with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template("index.html")

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form['email']
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        flash('Invalid email format! Please enter a valid email.', 'danger')
        return redirect(url_for('index'))

    otp = str(randint(100000, 999999))
    session['email'] = email

    user = User.query.filter_by(email=email).first()
    if user:
        user.otp = otp
    else:
        flash("Email is not registered. Please register first!", "danger")
        return redirect(url_for('register'))

    db.session.commit()

    msg = Message('Your OTP Code', sender=os.getenv("MAIL_USERNAME"), recipients=[email])
    msg.body = f"Your OTP code is: {otp}"
    mail.send(msg)

    flash('OTP sent to your email. Please check and verify.', 'success')
    return redirect(url_for('verify'))

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        user_otp = request.form['otp']
        email = session.get('email')

        user = User.query.filter_by(email=email).first()

        if user and user.otp == user_otp:
            user.is_verified = True
            user.otp = None
            db.session.commit()

            flash('Email verification successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP! Please try again.', 'danger')

    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not found. Please register first.', 'danger')
            return redirect(url_for('register'))

        if not user.is_verified:
            flash('Email is not verified. Please check your email.', 'danger')
            return redirect(url_for('verify'))

        if check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid password. Please try again.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/home')
def home():
    if 'user_id' not in session:
        flash('Please log in to access the home page.', 'warning')
        return redirect(url_for('login'))

    return render_template('home.html', email=session['email'])


@app.route('/users')
def show_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email is already registered. Try logging in.", "danger")
            return redirect(url_for('login'))


        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        otp = str(randint(100000, 999999))

        new_user = User(name=name, email=email, password=hashed_password, otp=otp, is_verified=False)
        db.session.add(new_user)
        db.session.commit()


        msg = Message('Your OTP Code', sender=os.getenv("MAIL_USERNAME"), recipients=[email])
        msg.body = f"Your OTP code is: {otp}"
        mail.send(msg)

        session['email'] = email
        flash('Registration successful! OTP sent to your email.', 'success')
        return redirect(url_for('verify'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)


