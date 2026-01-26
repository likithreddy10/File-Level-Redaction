from flask import Flask, render_template, request, redirect, send_from_directory, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

import os
import fitz  # PyMuPDF
import cv2

# ---------------- CONFIG ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Use /tmp for Render compatibility
UPLOAD_FOLDER = os.path.join("/tmp", "uploads")
DB_PATH = os.path.join(BASE_DIR, "database.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "supersecretkey_change_me_in_production"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20MB limit

db = SQLAlchemy(app)

# ---------------- LOGIN ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------------- USER MODEL ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- CREATE TABLES ----------------
with app.app_context():
    db.create_all()

# ---------------- HELPERS ----------------
def redact_pdf(input_path, output_path):
    doc = fitz.open(input_path)

    patterns = [
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        r"\b\d{10}\b"
    ]

    for page in doc:
        for pattern in patterns:
            matches = page.search_for(pattern)
            for rect in matches:
                page.add_redact_annot(rect, fill=(0, 0, 0))
        page.apply_redactions()

    doc.save(output_path)
    doc.close()


def blur_faces(input_path, output_path):
    img = cv2.imread(input_path)
    if img is None:
        raise Exception("Invalid image")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    face_cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    )

    faces = face_cascade.detectMultiScale(gray, 1.3, 5)

    for (x, y, w, h) in faces:
        roi = img[y:y+h, x:x+w]
        roi = cv2.GaussianBlur(roi, (99, 99), 30)
        img[y:y+h, x:x+w] = roi

    cv2.imwrite(output_path, img)

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash("User already exists")
            return redirect(url_for("register"))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registered successfully")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/upload_pdf", methods=["POST"])
@login_required
def upload_pdf():
    file = request.files.get("pdf")
    if not file:
        flash("No PDF selected")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    output_path = os.path.join(app.config["UPLOAD_FOLDER"], "redacted_" + filename)

    file.save(input_path)

    try:
        redact_pdf(input_path, output_path)
        return render_template("dashboard.html", pdf_file="redacted_" + filename)
    except Exception as e:
        flash(str(e))
        return redirect(url_for("dashboard"))

@app.route("/upload_image", methods=["POST"])
@login_required
def upload_image():
    file = request.files.get("image")
    if not file:
        flash("No image selected")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    output_path = os.path.join(app.config["UPLOAD_FOLDER"], "blurred_" + filename)

    file.save(input_path)

    try:
        blur_faces(input_path, output_path)
        return render_template("dashboard.html", image_file="blurred_" + filename)
    except Exception as e:
        flash(str(e))
        return redirect(url_for("dashboard"))

@app.route("/download/<filename>")
@login_required
def download(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True
    )

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
