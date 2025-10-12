from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename
import pandas as pd
import os
from datetime import datetime
from supabase import create_client, Client
from config import Config
import json

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Supabase client
supabase: Client = create_client(app.config['SUPABASE_URL'], app.config['SUPABASE_KEY'])

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def check_password(required_password):
    """Decorator to check password protection"""

    def decorator(f):
        def decorated_function(*args, **kwargs):
            if request.method == 'POST':
                password = request.form.get('password')
                if password != required_password:
                    flash('Incorrect password!', 'error')
                    return redirect(request.url)
            return f(*args, **kwargs)

        decorated_function.__name__ = f.__name__
        return decorated_function

    return decorator


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/event_upload', methods=['GET', 'POST'])
def event_upload():
    """Event upload page - upload Excel with reg numbers"""
    if request.method == 'POST':
        password = request.form.get('password')

        if password != app.config['EVENT_PASSWORD']:
            flash('Incorrect password!', 'error')
            return render_template('event_upload.html')

        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return render_template('event_upload.html')

        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return render_template('event_upload.html')

        if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
            try:
                # Read Excel file
                df = pd.read_excel(file)

                # Assume first column contains registration numbers
                reg_numbers = df.iloc[:, 0].astype(str).tolist()

                # Clear existing event registrations
                supabase.table('event_registrations').delete().neq('id', 0).execute()

                # Insert new registrations
                registrations = [{'reg_number': reg_num, 'uploaded_at': datetime.now().isoformat()}
                                 for reg_num in reg_numbers if pd.notna(reg_num)]

                if registrations:
                    supabase.table('event_registrations').insert(registrations).execute()
                    flash(f'Successfully uploaded {len(registrations)} registration numbers!', 'success')
                else:
                    flash('No valid registration numbers found in file!', 'error')

            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
        else:
            flash('Please upload an Excel file (.xlsx or .xls)', 'error')

    # Get current registrations
    try:
        result = supabase.table('event_registrations').select('*').order('uploaded_at', desc=True).execute()
        registrations = result.data
    except:
        registrations = []

    return render_template('event_upload.html', registrations=registrations)


@app.route('/clear_event_data', methods=['POST'])
def clear_event_data():
    """Clear event registration data (admin only)"""
    password = request.form.get('admin_password')

    if password != app.config['ADMIN_PASSWORD']:
        flash('Incorrect admin password!', 'error')
        return redirect(url_for('event_upload'))

    try:
        supabase.table('event_registrations').delete().neq('id', 0).execute()
        flash('Event registration data cleared successfully!', 'success')
    except Exception as e:
        flash(f'Error clearing data: {str(e)}', 'error')

    return redirect(url_for('event_upload'))


@app.route('/edit_registration', methods=['POST'])
def edit_registration():
    """Edit individual registration number"""
    registration_id = request.form.get('registration_id')
    new_reg_number = request.form.get('reg_number')

    try:
        supabase.table('event_registrations').update({
            'reg_number': new_reg_number
        }).eq('id', registration_id).execute()
        flash('Registration number updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating registration: {str(e)}', 'error')

    return redirect(url_for('event_upload'))


@app.route('/delete_registration', methods=['POST'])
def delete_registration():
    """Delete individual registration"""
    registration_id = request.form.get('registration_id')

    try:
        supabase.table('event_registrations').delete().eq('id', registration_id).execute()
        flash('Registration deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting registration: {str(e)}', 'error')

    return redirect(url_for('event_upload'))


@app.route('/scan_logs')
def scan_logs():
    """View scan logs - separate for lost & found and event entry"""
    try:
        # Get lost & found logs
        lost_found_result = supabase.table('lost_found_logs').select('*').order('scanned_at', desc=True).limit(
            100).execute()
        lost_found_logs = lost_found_result.data

        # Get authentication logs (you might need to create this table)
        auth_result = supabase.table('authentication_logs').select('*').order('scanned_at', desc=True).limit(
            100).execute()
        auth_logs = auth_result.data

    except Exception as e:
        flash(f'Error fetching logs: {str(e)}', 'error')
        lost_found_logs = []
        auth_logs = []

    return render_template('scan_logs.html',
                           lost_found_logs=lost_found_logs,
                           auth_logs=auth_logs)


@app.route('/admit_upload', methods=['GET', 'POST'])
def admit_upload():
    """Upload student admission data to database"""
    if request.method == 'POST':
        password = request.form.get('password')

        if password != app.config['ADMIN_PASSWORD']:
            flash('Incorrect password!', 'error')
            return render_template('admit_upload.html')

        if 'file' not in request.files:
            flash('No file selected!', 'error')
            return render_template('admit_upload.html')

        file = request.files['file']
        if file.filename == '':
            flash('No file selected!', 'error')
            return render_template('admit_upload.html')

        if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
            try:
                # Read Excel file
                df = pd.read_excel(file)

                # Expected columns: reg_number, student_name, email, department, card_uid
                required_columns = ['reg_number', 'student_name', 'email', 'card_uid']

                if not all(col in df.columns for col in required_columns):
                    flash(f'Excel file must contain columns: {", ".join(required_columns)}', 'error')
                    return render_template('admit_upload.html')

                # Prepare data for insertion
                students = []
                for _, row in df.iterrows():
                    student = {
                        'reg_number': str(row['reg_number']),
                        'student_name': str(row['student_name']),
                        'email': str(row['email']),
                        'card_uid': str(row['card_uid']).upper(),
                        'is_active': True,
                        'uploaded_at': datetime.now().isoformat()
                    }
                    students.append(student)

                if students:
                    # Insert in batches to avoid timeout
                    batch_size = 100
                    total_inserted = 0

                    for i in range(0, len(students), batch_size):
                        batch = students[i:i + batch_size]
                        supabase.table('registered_cards').upsert(batch).execute()
                        total_inserted += len(batch)

                    flash(f'Successfully uploaded {total_inserted} student records!', 'success')
                else:
                    flash('No valid student records found in file!', 'error')

            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
        else:
            flash('Please upload an Excel file (.xlsx or .xls)', 'error')

    return render_template('admit_upload.html')


# @app.route('/api/event_count')
# def event_count():
#     """API endpoint to get event registration count"""
#     try:
#         result = supabase.rpc('get_event_count').execute()
#         return jsonify({'count': result.data})
#     except Exception as e:
#         print(f"Error getting event count: {e}")
#         return jsonify({'count': 0})
#
#
# @app.route('/api/student_count')
# def student_count():
#     """API endpoint to get student count"""
#     try:
#         result = supabase.rpc('get_student_count').execute()
#         return jsonify({'count': result.data})
#     except Exception as e:
#         print(f"Error getting student count: {e}")
#         return jsonify({'count': 0})


if __name__ == '__main__':
    app.run(debug=True)
