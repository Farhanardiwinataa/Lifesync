# app.py - Updated models without patient role
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_socketio import SocketIO, emit
import re
from sqlalchemy import or_
from pymongo import MongoClient
from datetime import datetime


app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a random string in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///family_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)


# Inisialisasi koneksi MongoDB (gunakan nama yang berbeda dari 'db' SQLAlchemy)
mongo_client = MongoClient("mongodb+srv://21524059:8Ke5qjeY4XjdlBak@cluster0.c9rcmot.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
mongo_db = mongo_client['2']
mongo_collection = mongo_db['BPM']

# Custom Jinja2 filters
@app.template_filter('nl2br')
def nl2br_filter(text):
    """Convert newlines to HTML line breaks"""
    if not text:
        return text
    return text.replace('\n', '<br>\n')

# Add moment filter for date calculations
@app.template_global()
def moment():
    """Make datetime available in templates"""
    return datetime

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # hanya 'admin' dan 'user'
    monitored_patients = db.relationship('PatientData', backref='creator', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class PatientData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Tidak lagi tergantung pada User table untuk patient
    patient_identifier = db.Column(db.String(50), unique=True, nullable=False)  # Identifier unik untuk pasien
    full_name = db.Column(db.String(120), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    emergency_contact_name = db.Column(db.String(120), nullable=True)
    emergency_contact_phone = db.Column(db.String(20), nullable=True)
    medical_history = db.Column(db.Text, nullable=True)
    allergies = db.Column(db.Text, nullable=True)
    current_medications = db.Column(db.Text, nullable=True)
    blood_type = db.Column(db.String(5), nullable=True)
    weight = db.Column(db.Float, nullable=True)  # in kg
    height = db.Column(db.Float, nullable=True)  # in cm
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    created_by_user = db.relationship('User', foreign_keys=[created_by])

class AdminUserRelation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class UserPatientRelation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient_data.id'), nullable=False)  # Merujuk ke PatientData, bukan User
    
    # Relationships
    user = db.relationship('User', backref='patient_relations')
    patient = db.relationship('PatientData', backref='user_relations')

# Helper function to check admin authorization
def require_admin():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    return user

# Initialize database
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # Hanya izinkan role admin dan user
        if role not in ['admin', 'user']:
            flash('Invalid role selected!')
            return redirect(url_for('signup'))
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return redirect(url_for('signup'))
        
        # Create new user
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/api/patients/search')
def search_patients():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    results = PatientData.query.filter(
        or_(
            PatientData.full_name.ilike(f'%{query}%'),
            PatientData.patient_identifier.ilike(f'%{query}%')
        )
    ).all()

    return jsonify([
        {
            'id': patient.id,
            'full_name': patient.full_name,
            'patient_identifier': patient.patient_identifier,
            'gender': patient.gender,
            'birth_date': patient.birth_date.strftime('%Y-%m-%d')
        }
        for patient in results
    ])

@app.route('/api/user/<int:user_id>/patients')
def get_user_patients(user_id):
    relations = UserPatientRelation.query.filter_by(user_id=user_id).all()
    patients = [rel.patient for rel in relations]

    return jsonify([
        {
            'id': patient.id,
            'full_name': patient.full_name,
            'patient_identifier': patient.patient_identifier,
            'gender': patient.gender,
            'birth_date': patient.birth_date.strftime('%Y-%m-%d')
        }
        for patient in patients
    ])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash(f'Welcome back, {username}!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    role = user.role

    if role == 'admin':
        all_users = User.query.filter_by(role='user').all()
        relations = AdminUserRelation.query.filter_by(admin_id=user.id).all()
        linked_user_ids = [rel.user_id for rel in relations]
        
        # Get all patients data
        all_patients = PatientData.query.all()
        
        return render_template('admin_dashboard.html', 
                             user=user, 
                             users=all_users, 
                             linked_user_ids=linked_user_ids,
                             patients_data=all_patients)

    elif role == 'user':
        relations = UserPatientRelation.query.filter_by(user_id=user.id).all()
        patients = [rel.patient for rel in relations]  # Ambil PatientData objects
        admin_rel = AdminUserRelation.query.filter_by(user_id=user.id).first()
        head_nurse = User.query.get(admin_rel.admin_id) if admin_rel else None
        return render_template('user_dashboard.html', user=user, patients=patients, head_nurse=head_nurse)

    else:
        flash("Unknown role.")
        return redirect(url_for('logout'))

@app.route('/add_relation', methods=['GET', 'POST'])
def add_relation():
    if 'user_id' not in session:
        flash('Login terlebih dahulu.')
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])

    if current_user.role == 'admin':
        if request.method == 'POST':
            username = request.form.get('child_username')
            target = User.query.filter_by(username=username, role='user').first()
            if not target:
                flash('User tidak ditemukan atau bukan role user.')
                return redirect(url_for('add_relation'))

            existing = AdminUserRelation.query.filter_by(admin_id=current_user.id, user_id=target.id).first()
            if existing:
                flash('User ini sudah ditambahkan.')
            else:
                relation = AdminUserRelation(admin_id=current_user.id, user_id=target.id)
                db.session.add(relation)
                db.session.commit()
                flash(f'User {username} berhasil ditambahkan.')
            return redirect(url_for('dashboard'))

    elif current_user.role == 'user':
        if request.method == 'POST':
            patient_identifier = request.form.get('patient_identifier')
            target = PatientData.query.filter_by(patient_identifier=patient_identifier).first()
            if not target:
                flash('Pasien tidak ditemukan.')
                return redirect(url_for('add_relation'))

            existing = UserPatientRelation.query.filter_by(user_id=current_user.id, patient_id=target.id).first()
            if existing:
                flash('Pasien ini sudah ditambahkan.')
            else:
                relation = UserPatientRelation(user_id=current_user.id, patient_id=target.id)
                db.session.add(relation)
                db.session.commit()
                flash(f'Pasien {target.full_name} berhasil ditambahkan.')
            return redirect(url_for('dashboard'))

    else:
        flash('Role ini tidak memiliki izin untuk menambahkan relasi.')
        return redirect(url_for('dashboard'))

    return render_template('add_relation.html')

# Patient Data Management Routes (Admin Only)
@app.route('/admin/patient/add', methods=['GET', 'POST'])
def add_patient_data():
    admin_user = require_admin()
    if not isinstance(admin_user, User):
        return admin_user  # This is a redirect response
    
    if request.method == 'POST':
        try:
            # Generate unique patient identifier
            patient_identifier = request.form.get('patient_identifier')
            if not patient_identifier:
                # Auto-generate identifier if not provided
                base_identifier = request.form.get('full_name').replace(' ', '').lower()
                counter = 1
                patient_identifier = f"{base_identifier}_{counter:03d}"
                while PatientData.query.filter_by(patient_identifier=patient_identifier).first():
                    counter += 1
                    patient_identifier = f"{base_identifier}_{counter:03d}"
            
            # Check if patient identifier already exists
            existing_data = PatientData.query.filter_by(patient_identifier=patient_identifier).first()
            if existing_data:
                flash('Identifier pasien sudah ada. Gunakan identifier yang berbeda.')
                return redirect(url_for('add_patient_data'))
            
            # Parse birth date
            birth_date_str = request.form.get('birth_date')
            birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
            
            # Create new patient data
            patient_data = PatientData(
                patient_identifier=patient_identifier,
                full_name=request.form.get('full_name'),
                birth_date=birth_date,
                gender=request.form.get('gender'),
                phone_number=request.form.get('phone_number') or None,
                address=request.form.get('address') or None,
                emergency_contact_name=request.form.get('emergency_contact_name') or None,
                emergency_contact_phone=request.form.get('emergency_contact_phone') or None,
                medical_history=request.form.get('medical_history') or None,
                allergies=request.form.get('allergies') or None,
                current_medications=request.form.get('current_medications') or None,
                blood_type=request.form.get('blood_type') or None,
                weight=float(request.form.get('weight')) if request.form.get('weight') else None,
                height=float(request.form.get('height')) if request.form.get('height') else None,
                created_by=admin_user.id
            )
            
            db.session.add(patient_data)
            db.session.commit()
            
            flash(f'Data pasien {patient_data.full_name} berhasil ditambahkan dengan ID: {patient_identifier}')
            return redirect(url_for('dashboard'))
            
        except ValueError as e:
            flash(f'Error: Format data tidak valid. {str(e)}')
        except Exception as e:
            flash(f'Error: Gagal menyimpan data pasien. {str(e)}')
            db.session.rollback()
    
    return render_template('add_patient_data_new.html')

@app.route('/admin/patient/edit/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient_data(patient_id):
    admin_user = require_admin()
    if not isinstance(admin_user, User):
        return admin_user  # This is a redirect response
    
    patient_data = PatientData.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        try:
            # Parse birth date
            birth_date_str = request.form.get('birth_date')
            birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
            
            # Update patient data
            patient_data.patient_identifier = request.form.get('patient_identifier')
            patient_data.full_name = request.form.get('full_name')
            patient_data.birth_date = birth_date
            patient_data.gender = request.form.get('gender')
            patient_data.phone_number = request.form.get('phone_number') or None
            patient_data.address = request.form.get('address') or None
            patient_data.emergency_contact_name = request.form.get('emergency_contact_name') or None
            patient_data.emergency_contact_phone = request.form.get('emergency_contact_phone') or None
            patient_data.medical_history = request.form.get('medical_history') or None
            patient_data.allergies = request.form.get('allergies') or None
            patient_data.current_medications = request.form.get('current_medications') or None
            patient_data.blood_type = request.form.get('blood_type') or None
            patient_data.weight = float(request.form.get('weight')) if request.form.get('weight') else None
            patient_data.height = float(request.form.get('height')) if request.form.get('height') else None
            patient_data.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            flash(f'Data pasien {patient_data.full_name} berhasil diperbarui.')
            return redirect(url_for('dashboard'))
            
        except ValueError as e:
            flash(f'Error: Format data tidak valid. {str(e)}')
        except Exception as e:
            flash(f'Error: Gagal memperbarui data pasien. {str(e)}')
            db.session.rollback()
    
    return render_template('edit_patient_data_new.html', patient_data=patient_data)

@app.route('/admin/patient/delete/<int:patient_id>', methods=['POST'])
def delete_patient_data(patient_id):
    admin_user = require_admin()
    if not isinstance(admin_user, User):
        return admin_user  # This is a redirect response
    
    patient_data = PatientData.query.get_or_404(patient_id)
    
    try:
        patient_name = patient_data.full_name
        # Delete related relations first
        UserPatientRelation.query.filter_by(patient_id=patient_id).delete()
        db.session.delete(patient_data)
        db.session.commit()
        flash(f'Data pasien {patient_name} berhasil dihapus.')
    except Exception as e:
        flash(f'Error: Gagal menghapus data pasien. {str(e)}')
        db.session.rollback()
    
    return redirect(url_for('dashboard'))

@app.route('/admin/patient/view/<int:patient_id>')
def view_patient_data(patient_id):
    admin_user = require_admin()
    if not isinstance(admin_user, User):
        return admin_user  # This is a redirect response
    
    patient_data = PatientData.query.get_or_404(patient_id)
    return render_template('view_patient_data_new.html', patient_data=patient_data)

@app.route('/api/assign_patient', methods=['POST'])
def assign_patient_to_user():
    data = request.get_json()
    user_id = data.get('user_id')
    patient_id = data.get('patient_id')

    if not user_id or not patient_id:
        return jsonify({'message': 'user_id dan patient_id wajib diisi'}), 400

    # Cek apakah user dan pasien ada
    user = User.query.get(user_id)
    patient = PatientData.query.get(patient_id)

    if not user or not patient:
        return jsonify({'message': 'User atau pasien tidak ditemukan'}), 404

    # Cek apakah sudah ada relasi
    existing = UserPatientRelation.query.filter_by(user_id=user_id, patient_id=patient_id).first()
    if existing:
        return jsonify({'message': 'Relasi sudah ada'}), 400

    # Simpan relasi
    new_relation = UserPatientRelation(user_id=user_id, patient_id=patient_id)
    db.session.add(new_relation)
    db.session.commit()

    return jsonify({'message': 'Pasien berhasil ditambahkan'}), 200


@app.route('/api/patient/<patient_id>/heart_rate')
def get_patient_heart_rate(patient_id):
    results = mongo_collection.find({"patient_id": patient_id}).sort("timestamp", 1)

    # Konversi data ke format JSON untuk frontend
    heart_data = []
    for record in results:
        heart_data.append({
            "timestamp": record["timestamp"].strftime("%Y-%m-%d %H:%M"),
            "bpm": record["bpm"]
        })

    return jsonify(heart_data)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5050))
    socketio.run(app, debug=True, host="0.0.0.0", port=port)