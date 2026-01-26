from flask import Flask, render_template, request, redirect, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

import os
import re
import fitz  # PyMuPDF
import cv2

# ---------------- CONFIG ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20MB limit

db = SQLAlchemy(app)

# ---------------- LOGIN ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------------- USER MODEL ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        existing = User.query.filter_by(username=request.form["username"]).first()
        if existing:
            flash("Username already exists")
            return redirect("/register")

        user = User(username=request.form["username"], password=request.form["password"])
        db.session.add(user)
        db.session.commit()
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and user.password == request.form["password"]:
            login_user(user)
            return redirect("/dashboard")
        else:
            flash("Invalid credentials")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


# ---------------- PDF REDACTION ----------------
@app.route("/upload_pdf", methods=["POST"])
@login_required
def upload_pdf():
    file = request.files.get("pdf")
    if not file:
        return "No file uploaded", 400

    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    output_path = os.path.join(app.config["UPLOAD_FOLDER"], "redacted_" + filename)

    file.save(input_path)

    try:
        doc = fitz.open(input_path)

        patterns = [
            r'\b[6-9]\d{9}\b',
            r'\b\d{4}\s\d{4}\s\d{4}\b',
            r'\b\d{12}\b',
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
            r'https?://\S+|www\.\S+',
            r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
            r'\b(password|secret|apikey|token|confidential|otp)\b',
        ]

        for page in doc:
            text = page.get_text()
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    for rect in page.search_for(match):
                        page.add_redact_annot(rect, fill=(0, 0, 0))
            page.apply_redactions()

        doc.save(output_path)
        doc.close()

        return render_template("dashboard.html", pdf_file="redacted_" + filename)

    except Exception as e:
        return f"PDF Error: {str(e)}", 500


# ---------------- IMAGE FACE BLUR ----------------
def blur_faces(input_path, output_path):
    img = cv2.imread(input_path)
    if img is None:
        raise Exception("Invalid image")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")

    faces = face_cascade.detectMultiScale(gray, 1.3, 5)

    for (x, y, w, h) in faces:
        roi = img[y:y+h, x:x+w]
        roi = cv2.GaussianBlur(roi, (99, 99), 30)
        img[y:y+h, x:x+w] = roi

    cv2.imwrite(output_path, img)


@app.route("/upload_image", methods=["POST"])
@login_required
def upload_image():
    file = request.files.get("image")
    if not file:
        return "No image uploaded", 400

    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    output_path = os.path.join(app.config["UPLOAD_FOLDER"], "blurred_" + filename)

    file.save(input_path)

    try:
        blur_faces(input_path, output_path)
        return render_template("dashboard.html", image_file="blurred_" + filename)
    except Exception as e:
        return f"Image Error: {str(e)}", 500


# ---------------- DOWNLOAD ----------------
@app.route("/download/<filename>")
@login_required
def download(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)


# ---------------- INIT ----------------
if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    with app.app_context():
        db.create_all()

    app.run(host="0.0.0.0", port=10000)
