from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

import os
import re
import fitz   # PyMuPDF for PDF
import cv2    # OpenCV for image
from openpyxl import load_workbook

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

    patterns = [
        r'\b\d{10}\b',       # Phone numbers
        r'\b\d{12}\b',       # Aadhaar-like numbers
        r'\S+@\S+',          # Emails
    ]

    for page in doc:
        text = page.get_text()

        for pattern in patterns:
            matches = re.findall(pattern, text)

            for match in matches:
                areas = page.search_for(match)
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

    if __name__ == "__main__":
        app.run()
