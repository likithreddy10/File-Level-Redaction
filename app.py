from flask import Flask, render_template, request, redirect, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

import os
import re
import fitz
import cv2

app = Flask(__name__)
app.secret_key = "secretkey"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

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


# ---------------- BASIC ROUTES ----------------
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(username=request.form['username'], password=request.form['password'])
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password == request.form['password']:
            login_user(user)
            return redirect('/dashboard')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/login')


# ---------------- PDF REDACTION ----------------

@app.route('/upload_pdf', methods=['POST'])
@login_required
def upload_pdf():
    file = request.files['pdf']
    filename = secure_filename(file.filename)

    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'redacted_' + filename)

    file.save(input_path)

    doc = fitz.open(input_path)

    # Strong regex patterns
    patterns = [
        r'\b[6-9]\d{9}\b',                              # Indian phone
        r'\b\d{12}\b',                                  # Aadhaar continuous
        r'\b\d{4}\s\d{4}\s\d{4}\b',                     # Aadhaar spaced
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'https?://[^\s]+|www\.[^\s]+',                # URLs
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',                 # IP address
        r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',                   # PAN card
        r'\b[A-Z]{4}0[A-Z0-9]{6}\b',                    # IFSC code
        r'\b(?:\d[ -]*?){13,16}\b',                     # Card numbers
        r'\b(password|secret|apikey|token|confidential|private|otp)\b',  # Keywords
    ]

    for page in doc:
        text = page.get_text()

        for pattern in patterns:
            matches = re.findall(pattern, text, flags=re.IGNORECASE)

            for match in matches:
                areas = page.search_for(str(match))
                for area in areas:
                    page.add_redact_annot(area, fill=(0, 0, 0))

        page.apply_redactions()

    doc.save(output_path)

    return render_template("dashboard.html", pdf_file='redacted_' + filename)

# ---------------- IMAGE FACE BLUR ----------------
def blur_faces(input_path, output_path):
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    img = cv2.imread(input_path)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    faces = face_cascade.detectMultiScale(gray, 1.2, 4)

    for (x, y, w, h) in faces:
        roi = img[y:y+h, x:x+w]
        roi = cv2.GaussianBlur(roi, (99, 99), 30)
        img[y:y+h, x:x+w] = roi

    cv2.imwrite(output_path, img)

@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    file = request.files['image']
    filename = secure_filename(file.filename)

    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'blurred_' + filename)

    file.save(input_path)
    blur_faces(input_path, output_path)

    return render_template("dashboard.html", image_file='blurred_' + filename)


# ---------------- TEXT REDACTION ----------------
@app.route('/text_redaction', methods=['GET', 'POST'])
@login_required
def text_redaction():
    redacted_text = None

    if request.method == 'POST':
        original_text = request.form.get('text')
        redacted_text = original_text

        redacted_text = re.sub(r'\S+@\S+', '████', redacted_text)
        redacted_text = re.sub(r'\b\d{10}\b', '████', redacted_text)
        redacted_text = re.sub(r'\b\d{12}\b', '████', redacted_text)

    return render_template('text_redaction.html', redacted_text=redacted_text)


# ---------------- DOWNLOAD ----------------
@app.route('/download/<filename>')
@login_required
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# ---------------- MAIN ----------------
if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    with app.app_context():
        db.create_all()

    app.run(host="0.0.0.0", port=10000)
