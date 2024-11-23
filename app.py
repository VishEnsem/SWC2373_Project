from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from flask_wtf.csrf import CSRFProtect
from wtforms.validators import DataRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import secrets

# Initialize Flask app and database
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = "my-secrets"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///Conference_meeting.db"

# Setup database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Database model for user registration
class Register(UserMixin, db.Model):  # Added UserMixin for Flask-Login compatibility
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Define user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return Register.query.get(int(user_id))  # Load user by ID from the database

# Create tables
with app.app_context():
    db.create_all()

# Form for user registration
class UserRegistrationForm(FlaskForm):
    email = EmailField("Email Address", validators=[DataRequired(), Email()])
    username = StringField("Username", validators=[DataRequired(), Length(min=4, max=30)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=20)])

# Form for user login
class UserLoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])

# Routes
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    form = UserLoginForm()
    if form.validate_on_submit():
        user = Register.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid login details. Please try again.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def user_registration():
    form = UserRegistrationForm()
    if form.validate_on_submit():
        if Register.query.filter_by(email=form.email.data).first():
            flash("Email already registered.", "danger")
        else:
            new_user = Register(
                email=form.email.data,
                username=form.username.data,
                password=form.password.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Account created! You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("user_registration.html", form=form)

@app.route("/index")
@login_required
def index():
    return render_template("index.html", username=current_user.username)

@app.route("/meeting_room")
@login_required
def meeting_room():
    return render_template("meeting_room.html", username=current_user.username)

@app.route("/join_meeting", methods=["GET", "POST"])
@login_required
def join_meeting():
    if request.method == "POST":
        meeting_id = request.form.get("roomID")
        if meeting_id:
            return redirect(f"/meeting_room?roomID={meeting_id}")
        flash("Please provide a valid meeting ID.", "danger")
    return render_template("join_meeting.html")

if __name__ == "__main__":
    app.run(debug=True)
