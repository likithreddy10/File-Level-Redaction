from flask import Flask, render_template, request, redirect, send_from_directory, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

import os
import re
import fitz  # PyMuPDF
import cv2

# ---------------- CONFIG ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# 1. Ensure Upload Folder exists immediately on startup
# This is critical for Render as it starts with a clean filesystem
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)

# Use Environment Variable for Secret Key if available
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Check if Render provided a DATABASE_URL, otherwise use local SQLite
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Default to database.db in the base directory
app.config["SQLALCHEMY_DATABASE_URI"] = database_url or f"sqlite:///{os.path.join(BASE_DIR, 'database.db')}"
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
    # Using modern db.session.get for compatibility
    return db.session.get(User, int(user_id))


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        existing = User.query.filter_by(username=request.form["username"]).first()
        if existing:
            flash("Username already exists")
            return redirect(url_for("register"))

        user = User(username=request.form["username"], password=request.form["password"])
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and user.password == request.form["password"]:
            login_user(user)
            return redirect(url_for("dashboard"))
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
    return redirect(url_for("login"))


# ---------------- PDF REDACTION ----------------
@app.route("/upload_pdf", methods=["POST"])
@login_required
def upload_pdf():
    file = request.files.get("pdf")
    if not file:
        flash("No file uploaded")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    output_filename = "redacted_" + filename
    output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_filename)

    file.save(input_path)

    try:
        doc = fitz.open(input_path)

        # Common PII patterns
        patterns = [
            r'\b[6-9]\d{9}\b', # Phone numbers
            r'\b\d{4}\s\d{4}\s\d{4}\b', # Aadhaar style
            r'\b\d{12}\b', # Simple 12 digit IDs
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', # Emails
            r'https?://\S+|www\.\S+', # URLs
            r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', # PAN
            r'\b(password|secret|apikey|token|confidential|otp)\b',
        ]

        for page in doc:
            for pattern in patterns:
                # search_for returns a list of Rect objects
                rects = page.search_for(pattern)
                for rect in rects:
                    page.add_redact_annot(rect, fill=(0, 0, 0))
            page.apply_redactions()

        # Save with optimization
        doc.save(output_path, garbage=3, deflate=True)
        doc.close()

        # Pass the filename specifically for the download button in the template
        return render_template("dashboard.html", pdf_file=output_filename)

    except Exception as e:
        print(f"PDF Error: {str(e)}")
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
    output_filename = "blurred_" + filename
    output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_filename)

    file.save(input_path)

    try:
        blur_faces(input_path, output_path)
        return render_template("dashboard.html", image_file=output_filename)
    except Exception as e:
        return f"Image Error: {str(e)}", 500


# ---------------- DOWNLOAD ----------------
@app.route("/download/<filename>")
@login_required
def download(filename):
    # This route handles the actual file transfer from the 'uploads' folder
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)


# ---------------- INIT ----------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
