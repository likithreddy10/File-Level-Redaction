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
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)

# Security configuration - Use your Render environment variable first
app.secret_key = os.environ.get("SECRET_KEY", "p@ssw0rd_S3cur3_Redact_2024_!_#")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Database configuration
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

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
    return db.session.get(User, int(user_id))


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        existing = db.session.query(User).filter_by(username=request.form["username"]).first()
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
        user = db.session.query(User).filter_by(username=request.form["username"]).first()
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

        # RegEx patterns for common PII
        # Improved patterns to handle spaces and boundaries better
        patterns = [
            r'\b[6-9]\d{9}\b',                        # Phone numbers (10 digits starting with 6-9)
            r'\d{4}\s\d{4}\s\d{4}',                   # Aadhaar with exactly one space between 4 digits
            r'\d{12}',                                # 12-digit numbers
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', # Emails
            r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',             # PAN Card
            r'(?i)password|secret|apikey|token|confidential|otp', # Keywords (case insensitive)
        ]

        for page in doc:
            # 1. Search using predefined patterns
            for pattern in patterns:
                # Get the full text of the page to find regex matches first
                page_text = page.get_text("text")
                matches = re.finditer(pattern, page_text)
                
                for match in matches:
                    matched_text = match.group()
                    # Search for the specific matched text on the page to get coordinates
                    # Using quads=True helps with text that flows across lines
                    rects = page.search_for(matched_text)
                    for r in rects:
                        page.add_redact_annot(r, fill=(0, 0, 0))
            
            # 2. Apply all redactions for this page
            # We use 'images=fitz.PDF_REDACT_IMAGE_NONE' to focus only on text redaction
            page.apply_redactions()

        # Save with clean-up to ensure redactions are permanent and file is optimized
        doc.save(output_path, garbage=3, deflate=True)
        doc.close()

        return render_template("dashboard.html", pdf_file=output_filename)

    except Exception as e:
        print(f"PDF Error: {str(e)}")
        return f"PDF Error: {str(e)}", 500


# ---------------- IMAGE FACE BLUR ----------------
def blur_faces(input_path, output_path):
    img = cv2.imread(input_path)
    if img is None:
        raise Exception("Invalid image file")

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


# ---------------- DOWNLOAD ROUTE ----------------
@app.route("/download/<filename>")
@login_required
def download(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)


# ---------------- INIT ----------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
