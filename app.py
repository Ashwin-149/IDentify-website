from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename
import re
from datetime import timezone
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

def slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return s[:80]

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

@app.get('/events')
def events_list():
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        q = supabase.table('events').select('*').eq('is_active', True)
        events = q.order('start_at', desc=False).execute().data or []

        ids = [e['id'] for e in events]
        counts = {}
        if ids:
            reg_rows = supabase.table('event_registrations_user') \
                .select('event_id') \
                .in_('event_id', ids) \
                .eq('status', 'registered') \
                .execute().data or []
            for r in reg_rows:
                counts[r['event_id']] = counts.get(r['event_id'], 0) + 1

        for e in events:
            e['registered_count'] = counts.get(e['id'], 0)

        return render_template('events.html', events=events)
    except Exception as e:
        flash(f'Error loading events: {e}', 'error')
        return render_template('events.html', events=[])

@app.get('/events/<slug>')
def event_detail(slug):
    try:
        res = supabase.table('events').select('*').eq('slug', slug).single().execute()
        event = res.data
        if not event or not event.get('is_active', True):
            flash('Event not found or inactive', 'error')
            return redirect(url_for('events_list'))

        regs = supabase.table('event_registrations_user') \
            .select('id') \
            .eq('event_id', event['id']) \
            .eq('status', 'registered') \
            .execute().data or []
        registered_count = len(regs)

        return render_template('event_detail.html', event=event, registered_count=registered_count)
    except Exception as e:
        flash(f'Error loading event: {e}', 'error')
        return redirect(url_for('events_list'))

@app.post('/events/<slug>/register')
def event_register(slug):
    reg_number = (request.form.get('reg_number') or '').strip().upper()
    name = (request.form.get('name') or '').strip()
    email = (request.form.get('email') or '').strip()

    if not reg_number:
        flash('Registration number is required', 'error')
        return redirect(url_for('event_detail', slug=slug))

    try:
        ev_res = supabase.table('events').select('*').eq('slug', slug).single().execute()
        event = ev_res.data
        if not event or not event.get('is_active', True):
            flash('Event not found or inactive', 'error')
            return redirect(url_for('events_list'))

        cap = event.get('capacity') or 0
        current_regs = supabase.table('event_registrations_user') \
            .select('id') \
            .eq('event_id', event['id']) \
            .eq('status', 'registered') \
            .execute().data or []
        if cap > 0 and len(current_regs) >= cap:
            flash('Event is full', 'error')
            return redirect(url_for('event_detail', slug=slug))

        existing = supabase.table('event_registrations_user') \
            .select('id') \
            .eq('event_id', event['id']) \
            .eq('reg_number', reg_number) \
            .execute().data
        if existing:
            flash('You already registered for this event', 'info')
            return redirect(url_for('event_detail', slug=slug))

        supabase.table('event_registrations_user').insert({
            'event_id': event['id'],
            'reg_number': reg_number,
            'name': name,
            'email': email,
            'status': 'registered',
            'registered_at': datetime.now().isoformat()
        }).execute()

        flash('Registration successful!', 'success')
        return redirect(url_for('event_detail', slug=slug))
    except Exception as e:
        flash(f'Error registering: {e}', 'error')
        return redirect(url_for('event_detail', slug=slug))


@app.get('/admin/events')
def admin_events():
    events = []
    try:
        events = supabase.table('events').select('*').order('start_at', desc=False).execute().data or []
    except Exception as e:
        flash(f'Error loading events: {e}', 'error')
    return render_template('admin_events.html', events=events)

@app.post('/admin/events')
def admin_create_event():
    pw = request.form.get('password')
    if pw != app.config.get('EVENT_ADMIN_PASSWORD'):
        flash('Incorrect admin password', 'error')
        return redirect(url_for('admin_events'))

    title = (request.form.get('title') or '').strip()
    description = (request.form.get('description') or '').strip()
    start_at = (request.form.get('start_at') or '').strip()
    end_at = (request.form.get('end_at') or '').strip()
    location = (request.form.get('location') or '').strip()
    capacity = request.form.get('capacity')
    cover_url = (request.form.get('cover_url') or '').strip()

    if not title:
        flash('Title is required', 'error')
        return redirect(url_for('admin_events'))

    slug = slugify(title)
    try:
        cap_val = int(capacity) if capacity else None
    except:
        cap_val = None

    try:
        supabase.table('events').insert({
            'title': title,
            'slug': slug,
            'description': description,
            'start_at': start_at or None,
            'end_at': end_at or None,
            'location': location,
            'capacity': cap_val,
            'cover_url': cover_url,
            'is_active': True
        }).execute()
        flash('Event created', 'success')
    except Exception as e:
        flash(f'Error creating event: {e}', 'error')

    return redirect(url_for('admin_events'))

@app.post('/admin/events/<int:event_id>/toggle')
def admin_toggle_event(event_id):
    pw = request.form.get('password')
    if pw != app.config.get('EVENT_ADMIN_PASSWORD'):
        flash('Incorrect admin password', 'error')
        return redirect(url_for('admin_events'))

    try:
        ev = supabase.table('events').select('*').eq('id', event_id).single().execute().data
        if not ev:
            flash('Event not found', 'error')
            return redirect(url_for('admin_events'))

        new_state = not ev.get('is_active', True)
        supabase.table('events').update({'is_active': new_state}).eq('id', event_id).execute()
        flash('Event state updated', 'success')
    except Exception as e:
        flash(f'Error updating event: {e}', 'error')

    return redirect(url_for('admin_events'))

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
