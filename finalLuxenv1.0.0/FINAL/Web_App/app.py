import os
# Set environment variables
os.environ['AWS_ACCESS_KEY_ID'] = 'AKIAUMHDSKJ2ZE3IPDNA'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-2'
os.environ['AWS_SECRET_ACCESS_KEY'] = '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'
os.environ['GEMINI_API_KEY'] = 'AIzaSyDATlzkJ-auty-coYJEkcl1PoJFd1Vj13o'
os.environ['PYTHONUNBUFFERED'] = '1'
os.environ['S3_BUCKET_NAME'] = 'luxen-test-storage-v1'

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from werkzeug.utils import secure_filename
import time
import base64
import boto3
import pandas as pd
import matplotlib.pyplot as plt
import io
import uuid
from datetime import datetime
from server_2 import EczemaAnalyzer, S3_BUCKET, GEMINI_API_KEY, GEMINI_API_URL
import json
import urllib.parse

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'dcm', 'nii', 'nii.gz', 'jpg', 'jpeg', 'png'}

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize S3 client
s3 = boto3.client('s3')

# Initialize the EczemaAnalyzer
analyzer = EczemaAnalyzer(S3_BUCKET, GEMINI_API_KEY, GEMINI_API_URL)

print(f"S3_BUCKET: {S3_BUCKET}")
print(f"GEMINI_API_KEY: {GEMINI_API_KEY}")

# Define the fixed S3 folder for all data
S3_FIXED_FOLDER = 'luxenaibusiness@gmail.com/'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    with sqlite3.connect('luxen.db') as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                result TEXT,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                s3_key TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                redness REAL,
                scaling REAL,
                texture REAL,
                color_variation REAL,
                severity REAL
                predicted REAL
            )
        ''')

def verify_db():
    try:
        with sqlite3.connect('luxen.db') as conn:
            # Check if users table exists and has correct structure
            cursor = conn.execute("PRAGMA table_info(users)")
            columns = {row[1] for row in cursor.fetchall()}
            required_columns = {'id', 'email', 'password'}
            if not required_columns.issubset(columns):
                print("Recreating users table...")
                conn.execute('DROP TABLE IF EXISTS users')
                conn.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE,
                        password TEXT
                    )
                ''')
            
            # Check if scans table exists and has correct structure
            cursor = conn.execute("PRAGMA table_info(scans)")
            columns = {row[1] for row in cursor.fetchall()}
            required_columns = {'id', 'user_id', 'filename', 'result', 'upload_date', 's3_key'}
            if not required_columns.issubset(columns):
                print("Recreating scans table...")
                conn.execute('DROP TABLE IF EXISTS scans')
                conn.execute('''
                    CREATE TABLE scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        filename TEXT,
                        result TEXT,
                        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        s3_key TEXT
                    )
                ''')
            
            # Check if scan_results table exists and has correct structure
            cursor = conn.execute("PRAGMA table_info(scan_results)")
            columns = {row[1] for row in cursor.fetchall()}
            required_columns = {'id', 'timestamp', 'redness', 'scaling', 'texture', 'color_variation', 'severity', 'predicted'}
            if not required_columns.issubset(columns):
                print("Recreating scan_results table...")
                conn.execute('DROP TABLE IF EXISTS scan_results')
                conn.execute('''
                    CREATE TABLE scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        redness REAL,
                        scaling REAL,
                        texture REAL,
                        color_variation REAL,
                        severity REAL,
                        predicted REAL
                    )
                ''')
    except Exception as e:
        print(f"Database verification error: {str(e)}")
        raise

# Initialize and verify database
init_db()
verify_db()

def get_user_folder(email):
    """Get the S3 folder path for a user"""
    # URL encode the email to handle special characters
    safe_email = urllib.parse.quote(email, safe='')
    return f"{safe_email}/"

def save_user_to_s3(user_data):
    """Save user data to S3"""
    try:
        email = user_data['email']
        user_folder = get_user_folder(email)
        profile_key = f"{user_folder}profile.json"
        upload_to_s3(json.dumps(user_data).encode(), profile_key)
        return True
    except Exception as e:
        print(f"Error saving user to S3: {str(e)}")
        return False

def get_user_from_s3(email):
    """Get user data from S3"""
    try:
        user_folder = get_user_folder(email)
        profile_key = f"{user_folder}profile.json"
        response = s3.get_object(Bucket=S3_BUCKET, Key=profile_key)
        return json.loads(response['Body'].read().decode())
    except Exception as e:
        print(f"Error getting user from S3: {str(e)}")
        return None

def delete_user_from_s3(email):
    """Delete user data from S3"""
    try:
        user_folder = get_user_folder(email)
        response = s3.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=user_folder
        )
        if 'Contents' in response:
            delete_objects = [{'Key': obj['Key']} for obj in response['Contents']]
            s3.delete_objects(
                Bucket=S3_BUCKET,
                Delete={'Objects': delete_objects, 'Quiet': True}
            )
        return True
    except Exception as e:
        print(f"Error deleting user from S3: {str(e)}")
        return False

def upload_to_s3(file_data, s3_key):
    """Upload file data to S3"""
    try:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=file_data
        )
        return True
    except Exception as e:
        print(f"Error uploading to S3: {str(e)}")
        return False

def get_from_s3(s3_key):
    """Get file data from S3"""
    try:
        response = s3.get_object(
            Bucket=S3_BUCKET,
            Key=s3_key
        )
        return response['Body'].read()
    except Exception as e:
        print(f"Error getting from S3: {str(e)}")
        return None

def delete_from_s3(s3_key):
    """Delete file from S3"""
    try:
        s3.delete_object(
            Bucket=S3_BUCKET,
            Key=s3_key
        )
        return True
    except Exception as e:
        print(f"Error deleting from S3: {str(e)}")
        return False

def analyze_scan(file_data, filename):
    """Analyze a scan using Gemini AI and return metrics."""
    try:
        metrics = analyzer.get_gemini_analysis_results(file_data)
        formatted_metrics = {
            'redness_level': metrics['Redness Level'],
            'scaling_level': metrics['Scaling Level'],
            'texture_score': metrics['Texture Score'],
            'color_variation': metrics['Color Variation'],
            'severity_score': metrics['Severity Score'],
            'predicted_deficiency': metrics['Predicted Deficiency']
        }
        return str(formatted_metrics)
    except Exception as e:
        print(f"Analysis error: {str(e)}")
        return str({
            'redness_level': 0,
            'scaling_level': 0,
            'texture_score': 0,
            'color_variation': 0,
            'severity_score': 0,
            'predicted_deficiency': 0
        })

def save_scan_data(email, filename, result, file_data=None):
    """Save scan file, analysis result to S3 and scan record to database."""
    try:
        user_folder = get_user_folder(email)
        timestamp = datetime.utcnow().isoformat()

        # Save scan file to S3
        scan_key = f"{user_folder}scans/{filename}"
        if file_data and not upload_to_s3(file_data, scan_key):
            print(f"Error uploading scan file {filename} to S3")
            return False

        # Save analysis result to S3
        analysis_key = f"{user_folder}analysis/{filename}_analysis.json"
        analysis_data = {
            'timestamp': timestamp,
            'filename': filename,
            'result': result
        }
        if not upload_to_s3(json.dumps(analysis_data).encode(), analysis_key):
            print(f"Error uploading analysis for {filename} to S3")
            # Consider deleting the scan file if analysis upload fails
            return False

        # Save record to database
        with sqlite3.connect('luxen.db') as conn:
            conn.execute('INSERT INTO scans (user_id, filename, result, s3_key) VALUES (?, ?, ?, ?)',
                        (session['user_id'], filename, result, scan_key))
        return True

    except Exception as e:
        print(f"Error in save_scan_data: {str(e)}")
        return False

def save_metrics_and_graph(redness, scaling, texture, color_variation, severity, predicted_deficiency):
    timestamp = datetime.utcnow().isoformat()
    with sqlite3.connect('luxen.db') as conn:
        conn.execute('INSERT INTO scan_results (timestamp, redness, scaling, texture, color_variation, severity, predicted_deficiency) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (timestamp, redness, scaling, texture, color_variation, severity, predicted_deficiency))
    fig, ax = plt.subplots(figsize=(10, 6))
    labels = ['Redness', 'Scaling', 'Texture', 'Color', 'Severity', 'Predicted Deficiency']
    values = [redness, scaling, texture, color_variation, severity, predicted_deficiency]
    ax.plot(labels, values, 'o-', color='skyblue', linewidth=2, markersize=8)
    ax.set_title(f'Skin Traits - {timestamp[:19]} UTC')
    ax.set_ylim(0, 100)
    ax.grid(True, linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close(fig)
    # Note: Graph is not saved per user in this current structure
    # If needed per user, get user email here and construct s3_key accordingly
    s3_key = f"graphs/scan_report_{timestamp}.png"
    upload_to_s3(buf.getvalue(), s3_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        with sqlite3.connect('luxen.db') as conn:
            try:
                cursor = conn.execute('INSERT INTO users (email, password) VALUES (?, ?)',
                                    (email, password))
                user_id = cursor.lastrowid
                user_data = {
                    'id': user_id,
                    'email': email,
                    'password_hash': password,
                    'created_at': datetime.utcnow().isoformat(),
                    'last_login': None,
                    'scans': []
                }
                if save_user_to_s3(user_data):
                    flash('Account created successfully! Please log in.', 'success')
                    return redirect('/login')
                else:
                    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
                    flash('Error creating account. Please try again.', 'error')
                    return redirect('/signup')
            except sqlite3.IntegrityError:
                flash('Email already exists. Please try another email.', 'error')
                return redirect('/signup')
            except Exception as e:
                flash('An unexpected error occurred during signup.', 'error')
                print(f"Signup error: {str(e)}")
                return redirect('/signup')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            with sqlite3.connect('luxen.db') as conn:
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                if user and check_password_hash(user[2], password):
                    session['user_id'] = user[0]
                    session['user_email'] = user[1] # Store email in session
                    user_data = get_user_from_s3(email)
                    if user_data:
                        user_data['last_login'] = datetime.utcnow().isoformat()
                        save_user_to_s3(user_data)
                    return redirect('/dashboard')
                flash('Invalid email or password.', 'error')
                return redirect('/login')
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'error')
            return redirect('/login')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or 'user_email' not in session:
        return redirect('/login')
    
    user_email = session['user_email']

    if request.method == 'POST':
        if 'camera_capture' in request.form:
            try:
                image_data = request.form['camera_capture']
                if image_data.startswith('data:image/png;base64,'):
                    image_data = image_data.replace('data:image/png;base64,', '')
                filename = f"camera_capture_{int(time.time())}.png"
                file_data = base64.b64decode(image_data)
                result = analyze_scan(file_data, filename)
                
                if save_scan_data(user_email, filename, result, file_data=file_data):
                     flash('Photo captured and analyzed successfully!', 'success')
                else:
                     flash('Error saving captured photo.', 'error')

            except Exception as e:
                flash('Error saving captured photo. Please try again.', 'error')
                print(f"Camera capture error: {str(e)}")
            return redirect('/dashboard')

        if 'scan' not in request.files:
            flash('No file selected.', 'error')
            return redirect('/dashboard')
        
        file = request.files['scan']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect('/dashboard')
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"{os.path.splitext(filename)[0]}_{int(time.time())}{os.path.splitext(filename)[1]}"
            
            try:
                file_data = file.read()
                result = analyze_scan(file_data, filename)
                
                if save_scan_data(user_email, filename, result, file_data=file_data):
                    flash('File uploaded and analyzed successfully!', 'success')
                else:
                    flash('Error uploading file.', 'error')

            except Exception as e:
                flash('Error uploading file. Please try again.', 'error')
                print(f"Upload error: {str(e)}")
        else:
            flash('Invalid file type. Please upload a supported medical image format.', 'error')
    
    with sqlite3.connect('luxen.db') as conn:
        scans = conn.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY upload_date DESC', (session['user_id'],)).fetchall()
    return render_template('dashboard.html', scans=scans)

@app.route('/delete_scan', methods=['POST'])
def delete_scan():
    if 'user_id' not in session or 'user_email' not in session:
        return redirect('/login')
    
    scan_id = request.form['scan_id']
    user_id = session['user_id']
    user_email = session['user_email']

    try:
        with sqlite3.connect('luxen.db') as conn:
            # Get S3 key and filename before deleting from DB
            scan = conn.execute('SELECT s3_key, filename FROM scans WHERE id=? AND user_id=?', 
                              (scan_id, user_id)).fetchone()
            
            if scan:
                s3_key = scan[0] # This should be the scan file key (e.g., useremail/scans/filename)
                filename = scan[1]
                user_folder = get_user_folder(user_email)
                
                # Construct the analysis key based on the scan filename
                analysis_key = f"{user_folder}analysis/{filename}_analysis.json"

                # Delete from S3 (scan file and analysis file)
                deleted_scan = delete_from_s3(s3_key)
                deleted_analysis = delete_from_s3(analysis_key)

                if deleted_scan and deleted_analysis:
                    # Delete from database
                    conn.execute('DELETE FROM scans WHERE id=? AND user_id=?', 
                               (scan_id, user_id))
                    flash('Scan and analysis deleted successfully.', 'success')
                elif deleted_scan or deleted_analysis:
                     flash('Partial deletion: Check S3 bucket.', 'warning')
                     # Still delete from DB if at least one S3 file was deleted
                     conn.execute('DELETE FROM scans WHERE id=? AND user_id=?', 
                               (scan_id, user_id))
                else:
                    flash('Error deleting scan from S3.', 'error')
    except Exception as e:
        flash('Error deleting scan. Please try again.', 'error')
        print(f"Delete error: {str(e)}")
    
    return redirect('/dashboard')

@app.route('/report/<int:scan_id>')
def report(scan_id):
    if 'user_id' not in session or 'user_email' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_email = session['user_email']

    with sqlite3.connect('luxen.db') as conn:
        scan = conn.execute('SELECT * FROM scans WHERE id=? AND user_id=?', 
                          (scan_id, user_id)).fetchone()
    if not scan:
        flash('Scan not found.', 'error')
        return redirect('/dashboard')
    
    # Retrieve the analysis result from S3
    filename = scan[2] # filename is at index 2 in the scan tuple
    user_folder = get_user_folder(user_email)
    analysis_key = f"{user_folder}analysis/{filename}_analysis.json"
    analysis_data = get_from_s3(analysis_key)

    if analysis_data:
        scan_result = json.loads(analysis_data.decode()).get('result', 'Analysis data not found in S3.')
    else:
        scan_result = 'Analysis data not found in S3.'
        flash('Analysis data not found for this scan.', 'warning')

    # Pass the retrieved analysis result to the template
    return render_template('report.html', scan=scan, scan_result=scan_result)

@app.route('/api/scan-metrics')
def scan_metrics():
    if 'user_id' not in session or 'user_email' not in session:
        return {'error': 'Not authenticated'}, 401
    
    user_id = session['user_id']
    user_email = session['user_email']

    with sqlite3.connect('luxen.db') as conn:
        scans = conn.execute('''
            SELECT filename, upload_date, result 
            FROM scans 
            WHERE user_id = ? 
            ORDER BY upload_date ASC
        ''', (user_id,)).fetchall()
    
    metrics = []
    for scan in scans:
        try:
            filename = scan[0]
            upload_date = scan[1]
            # Retrieve analysis result from S3 instead of DB result column
            user_folder = get_user_folder(user_email)
            analysis_key = f"{user_folder}analysis/{filename}_analysis.json"
            analysis_data = get_from_s3(analysis_key)

            if analysis_data:
                result = json.loads(analysis_data.decode()).get('result', {})
                if result:
                    metrics.append({
                        'timestamp': upload_date,
                        'Redness Level': result.get('redness_level', 0),
                        'Scaling Level': result.get('scaling_level', 0),
                        'Texture Score': result.get('texture_score', 0),
                        'Color Variation': result.get('color_variation', 0),
                        'Severity Score': result.get('severity_score', 0),
                        'Predicted Deficiency': result.get('predicted_deficiency')
                    })
            else:
                print(f"Analysis data not found in S3 for scan: {filename}")

        except Exception as e:
            print(f"Error processing scan metrics for {scan[0]}: {str(e)}")
            continue
    
    return jsonify(metrics)

@app.route('/api/s3-graphs')
def list_s3_graphs():
    # This route lists global graphs, not tied to a specific user folder structure yet
    try:
        s3 = boto3.client('s3')
        # Assuming graphs are still stored in a global 'graphs/' folder
        response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix="graphs/")
        files = []
        for obj in response.get('Contents', []):
            key = obj['Key']
            if key.endswith('.png') or key.endswith('.jpg'):
                url = f"https://{S3_BUCKET}.s3.amazonaws.com/{key}" # Direct S3 URL might not work if bucket is not public
                # It's better to generate a presigned URL here too
                url = s3.generate_presigned_url('get_object', Params={'Bucket': S3_BUCKET, 'Key': key}, ExpiresIn=3600)
                files.append(url)
        return jsonify(files[::-1])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/submit-scan', methods=['POST'])
def submit_scan():
    if 'user_id' not in session or 'user_email' not in session:
        return redirect('/login')

    # This route seems to be for manual metric submission, not tied to a scan file upload.
    # It saves metrics to the DB and generates a graph.
    # If you want this graph to be user-specific, you'll need to modify save_metrics_and_graph.

    redness = float(request.form.get('redness', 2.5))
    scaling = float(request.form.get('scaling', 2.0))
    texture = float(request.form.get('texture', 3.0))
    color_variation = float(request.form.get('color_variation', 2.8))
    severity = float(request.form.get('severity', 3.5))
    predicted_deficiency = request.form.get('predicted_deficiency', 'Unknown')

    save_metrics_and_graph(redness, scaling, texture, color_variation, severity, predicted_deficiency)
    flash('Scan metrics submitted successfully!', 'success')
    return redirect('/dashboard')

@app.route('/bulk_delete', methods=['POST'])
def bulk_delete():
    if 'user_id' not in session or 'user_email' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_email = session['user_email']

    try:
        scan_ids = json.loads(request.form['scan_ids'])
        if not scan_ids:
            flash('No scans selected for deletion.', 'warning')
            return redirect('/dashboard')

        with sqlite3.connect('luxen.db') as conn:
            # Get S3 keys and filenames before deleting from DB
            # Ensure only scans owned by the current user are selected
            placeholders = ','.join('?' * len(scan_ids))
            scans_to_delete = conn.execute(f'SELECT s3_key, filename FROM scans WHERE id IN ({placeholders}) AND user_id=?', 
                                         scan_ids + [user_id]).fetchall()
            
            if not scans_to_delete:
                 flash('No matching scans found for deletion.', 'warning')
                 return redirect('/dashboard')

            objects_to_delete = []
            user_folder = get_user_folder(user_email)

            for scan in scans_to_delete:
                s3_key = scan[0] # Scan file key
                filename = scan[1]
                analysis_key = f"{user_folder}analysis/{filename}_analysis.json"
                objects_to_delete.append({'Key': s3_key})
                objects_to_delete.append({'Key': analysis_key})

            # Delete from S3 in bulk
            if objects_to_delete:
                delete_response = s3.delete_objects(
                    Bucket=S3_BUCKET,
                    Delete={'Objects': objects_to_delete, 'Quiet': True}
                )

                # Check for errors during S3 deletion (Optional, depends on Quiet=True)
                # if 'Errors' in delete_response:
                #    print(f"Partial S3 deletion errors: {delete_response['Errors']}")
                #    flash('Partial deletion from S3. Check logs.', 'warning')

            # Delete from database
            conn.execute(f'DELETE FROM scans WHERE id IN ({placeholders}) AND user_id=?', 
                       scan_ids + [user_id])
            
            flash(f'Successfully deleted {len(scans_to_delete)} scan(s) and their analysis.', 'success')

    except json.JSONDecodeError:
        flash('Invalid scan selection data.', 'error')
    except Exception as e:
        flash('Error deleting scans. Please try again.', 'error')
        print(f"Bulk delete error: {str(e)}")
    
    return redirect('/dashboard')

@app.route('/s3-browser')
def s3_browser():
    if 'user_id' not in session or 'user_email' not in session:
        return redirect('/login')
    
    user_email = session['user_email']
    user_folder = get_user_folder(user_email)

    try:
        # List all objects in the user's folder
        response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=user_folder)
        files = []
        
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                # Exclude the user's main folder key itself if it appears
                if key == user_folder:
                    continue

                last_modified = obj['LastModified']
                size = obj['Size']
                
                # Determine file type based on the key path within the user folder
                file_type = "Unknown"
                if key == f"{user_folder}profile.json":
                    file_type = "User Profile"
                elif key.startswith(f"{user_folder}scans/"):
                    file_type = "Scan File"
                elif key.startswith(f"{user_folder}analysis/"):
                    file_type = "Analysis Data"
                elif key.startswith(f"{user_folder}graphs/"): # If graphs were user-specific
                     file_type = "Graph"

                # Generate a temporary URL for viewing/downloading
                url = s3.generate_presigned_url('get_object',
                    Params={'Bucket': S3_BUCKET, 'Key': key},
                    ExpiresIn=3600)  # URL expires in 1 hour
                
                files.append({
                    'key': key,
                    'last_modified': last_modified,
                    'size': size,
                    'type': file_type,
                    'url': url
                })
        
        # Optional: Sort files for better display (e.g., by key or last modified)
        # files.sort(key=lambda x: x['last_modified'], reverse=True)

        return render_template('s3_browser.html', files=files)
    except Exception as e:
        flash(f'Error accessing S3 bucket: {str(e)}', 'error')
        print(f"S3 Browser error: {str(e)}")
        return redirect('/dashboard')

if __name__ == '__main__':
    # Consider adding a check here if the S3 bucket exists or is accessible on startup
    # This might require AWS credentials to be set before this check
    app.run(debug=True, port=5001)
