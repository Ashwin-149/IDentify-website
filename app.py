from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response
from werkzeug.utils import secure_filename
from datetime import timezone, timedelta
import pandas as pd
import os
from datetime import datetime
from supabase import create_client, Client
from config import Config
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from functools import wraps
from zoneinfo import ZoneInfo
import csv
from io import StringIO

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Login manager
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

# Initialize Supabase client
supabase: Client = create_client(app.config['SUPABASE_URL'], app.config['SUPABASE_KEY'])

# Create uploads directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class AdminUser(UserMixin):
    def __init__(self, row):
        self.id = str(row['id'])
        self.email = row['email']
        self.is_active_flag = row.get('is_active', True)

    def is_active(self):
        return self.is_active_flag

@login_manager.user_loader
def load_user(user_id):
    try:
        res = supabase.table('admin_users').select('*').eq('id', int(user_id)).single().execute()
        row = res.data
        if not row:
            return None
        return AdminUser(row)
    except Exception:
        return None

@app.before_request
def make_session_non_permanent():
    session.permanent = False

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def nocache(view):
    @wraps(view)
    def no_cache_wrapper(*args, **kwargs):
        resp = make_response(view(*args, **kwargs))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
    return no_cache_wrapper

# Store images
ALLOWED_IMG_EXTS = {'.png', '.jpg', '.jpeg', '.webp', '.gif'}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def is_allowed_image(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_IMG_EXTS

def upload_to_supabase_storage(bucket: str, path: str, file_bytes: bytes, content_type: str):
    storage = supabase.storage.from_(bucket)
    try_path = path
    idx = 1
    while True:
        try:

            storage.upload(
                try_path,
                file_bytes,
                {"content-type": (content_type or "application/octet-stream")}
            )
            break
        except Exception as e:
            print(f"[upload] error uploading {try_path}: {e}")
            # Handle only clear name conflicts; otherwise re-raise for visibility
            if "exists" in str(e) or "409" in str(e):
                base, ext = os.path.splitext(path)
                try_path = f"{base}_{idx}{ext}"
                idx += 1
                if idx > 5:
                    raise
            else:
                raise

    public_url = storage.get_public_url(try_path)
    return public_url

LOCAL_TZ = ZoneInfo("Asia/Kolkata")  # change if needed

def pretty_dt(s: str) -> str:
    if not s:
        return ""
    s = s.strip()
    dt = None

    # 1) Normalize common ISO variants
    try:
        # Handle trailing Z (UTC)
        if s.endswith('Z'):
            dt = datetime.fromisoformat(s[:-1] + '+00:00')
        else:
            dt = datetime.fromisoformat(s)
    except ValueError:
        pass

    # 2) Try datetime-local formats
    if dt is None:
        for fmt in ("%Y-%m-%dT%H:%M",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M",
                    "%Y/%m/%d %H:%M"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue

    # 3) Try ISO with milliseconds by trimming fractional seconds if present
    if dt is None and '.' in s:
        try:
            s2 = s
            # Trim fractional part but keep timezone if any
            if '+' in s2:
                base, tz = s2.split('+', 1)
                s2 = base.split('.', 1)[0] + '+' + tz
            elif 'Z' in s2:
                base = s2.split('Z', 1)[0]
                s2 = base.split('.', 1)[0] + 'Z'
            else:
                s2 = s2.split('.', 1)[0]
            if s2.endswith('Z'):
                dt = datetime.fromisoformat(s2[:-1] + '+00:00')
            else:
                dt = datetime.fromisoformat(s2)
        except Exception:
            pass

    if dt is None:
        # Last resort: show as-is so you can spot unexpected formats
        return s

    # 4) Convert to local tz for display
    if dt.tzinfo is None:
        dt_local = dt.replace(tzinfo=LOCAL_TZ)
    else:
        dt_local = dt.astimezone(LOCAL_TZ)

    # 5) Cross-platform 12h hour without leading zero
    hour_fmt = "%-I"  # Unix
    try:
        # Some Windows builds error on %-I
        _ = dt_local.strftime(hour_fmt)
    except Exception:
        hour_fmt = "%#I"  # Windows

    return dt_local.strftime(f"%d %b %Y {hour_fmt}:%M %p")

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

@app.get('/admin/register')
@nocache
@login_required
def admin_register_form():
    # prevent showing register if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('admin_events'))
    return render_template('admin_register.html')

@app.post('/admin/register')
@nocache
@login_required
def admin_register():
    secret = (request.form.get('secret_code') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    confirm = request.form.get('confirm_password') or ''

    # Check secret code
    if secret != app.config.get('ADMIN_REGISTRATION_CODE'):
        flash('Invalid registration code.', 'error')
        return redirect(url_for('admin_register_form'))

    # Basic validation
    if not EMAIL_RE.match(email):
        flash('Please enter a valid email.', 'error')
        return redirect(url_for('admin_register_form'))
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('admin_register_form'))
    if password != confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('admin_register_form'))

    # Ensure unique email
    try:
        existing = supabase.table('admin_users').select('id').eq('email', email).single().execute().data
        if existing:
            flash('An admin with this email already exists.', 'error')
            return redirect(url_for('admin_register_form'))
    except Exception:
        # If select throws because not found, continue
        pass

    # Insert new admin with hashed password
    try:
        pwd_hash = generate_password_hash(password)
        res = supabase.table('admin_users').insert({
            'email': email,
            'password_hash': pwd_hash,
            'is_active': True
        }).execute()
        row = res.data[0]
        # Auto-login after registration (optional)
        user = AdminUser(row)
        login_user(user, remember=True)
        flash('Admin account created and logged in.', 'success')
        return redirect(url_for('admin_events'))
    except Exception as e:
        flash(f'Registration error: {e}', 'error')
        return redirect(url_for('admin_register_form'))

@app.get('/admin/login')
def admin_login_form():
    if current_user.is_authenticated:
        return redirect(url_for('admin_events'))
    return render_template('admin_login.html')

@app.post('/admin/login')
def admin_login():
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    try:
        res = supabase.table('admin_users').select('*').eq('email', email).single().execute()
        row = res.data
        if not row or not row.get('is_active', True):
            flash('Invalid credentials', 'error')
            return redirect(url_for('admin_login_form'))
        if not check_password_hash(row['password_hash'], password):
            flash('Invalid credentials', 'error')
            return redirect(url_for('admin_login_form'))
        user = AdminUser(row)
        login_user(user, remember=True)
        flash('Logged in successfully', 'success')
        next_url = request.args.get('next') or url_for('admin_events')
        return redirect(next_url)
    except Exception as e:
        flash('Login error', 'error')
        return redirect(url_for('admin_login_form'))

@app.post('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    resp = make_response(redirect(url_for('admin_login_form')))
    # Force-remove remember cookie
    resp.delete_cookie('remember_token', path='/', samesite='Lax')
    return resp

@app.route('/event_upload', methods=['GET', 'POST'])
@login_required
def event_upload():
    """Event upload page - upload Excel with reg numbers"""
    if request.method == 'POST':
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
@login_required
@nocache
def clear_event_data():
    """Clear event registration data (admin only)"""
    try:
        supabase.table('event_registrations').delete().neq('id', 0).execute()
        flash('Event registration data cleared successfully!', 'success')
    except Exception as e:
        flash(f'Error clearing data: {str(e)}', 'error')

    return redirect(url_for('event_upload'))


@app.route('/edit_registration', methods=['POST'])
@login_required
@nocache
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
@login_required
@nocache
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
@login_required
@nocache
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
@login_required
@nocache
def admit_upload():
    """Upload student admission data to database"""
    if request.method == 'POST':
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
            e['start_pretty'] = pretty_dt(e.get('start_at') or "")
            e['end_pretty'] = pretty_dt(e.get('end_at') or "")

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
        event['start_pretty'] = pretty_dt(event.get('start_at') or "")
        event['end_pretty'] = pretty_dt(event.get('end_at') or "")

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
@login_required
@nocache
def admin_events():
    events = []
    try:
        events = supabase.table('events').select('*').order('start_at', desc=False).execute().data or []
    except Exception as e:
        flash(f'Error loading events: {e}', 'error')
    return render_template('admin_events.html', events=events)

@app.post('/admin/events')
@login_required
@nocache
def admin_create_event():
    # 1) Read form fields
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
    except Exception:
        cap_val = None

    # 2) Create the event first
    try:
        ins = supabase.table('events').insert({
            'title': title,
            'slug': slug,
            'description': description,  # may be appended with <img> below
            'start_at': start_at or None,
            'end_at': end_at or None,
            'location': location,
            'capacity': cap_val,
            'cover_url': cover_url,
            'is_active': True
        }).execute()
        if not ins or not ins.data or len(ins.data) == 0:
            flash('Event creation failed: empty response', 'error')
            return redirect(url_for('admin_events'))
        event = ins.data[0]
        print(f"[admin] event created id={event.get('id')} slug={event.get('slug')}")
    except Exception as e:
        print(f"[admin] event insert error: {e}")
        flash(f'Error creating event: {e}', 'error')
        return redirect(url_for('admin_events'))

    # 3) Process image uploads
    files = request.files.getlist('images')
    print(f"[upload] received files: {len(files)}")
    appended_html = ""
    uploaded_any = False

    for f in files:
        if not f or f.filename.strip() == "":
            continue

        filename = secure_filename(f.filename)
        ext = os.path.splitext(filename)[1].lower()
        print(f"[upload] candidate file: {filename} mimetype={f.mimetype} ext={ext}")

        # Validate extension
        if ext not in ALLOWED_IMG_EXTS:
            print(f"[upload] skipped non-image or unsupported ext: {filename}")
            continue

        # Read bytes
        try:
            content = f.read()
        except Exception as e:
            print(f"[upload] read error for {filename}: {e}")
            continue

        if not content:
            print(f"[upload] empty content: {filename}")
            continue

        content_type = f.mimetype or 'application/octet-stream'
        store_path = f"{slug}/{filename}"

        try:
            public_url = upload_to_supabase_storage(
                app.config['EVENTS_BUCKET'],
                store_path,
                content,
                content_type
            )
            print(f"[upload] uploaded url: {public_url}")
        except Exception as e:
            print(f"[upload] upload helper error for {store_path}: {e}")
            public_url = None

        if public_url:
            uploaded_any = True
            appended_html += (
                f'\n<p><img src="{public_url}" alt="Event Image" '
                f'style="max-width:100%;border-radius:8px;"></p>\n'
            )

    # 4) Update description only if images were uploaded
    if uploaded_any and appended_html:
        new_desc = (description or '') + "\n" + appended_html
        try:
            supabase.table('events').update({'description': new_desc}).eq('id', event['id']).execute()
            print(f"[upload] description updated with images, total appended chars={len(appended_html)}")
        except Exception as e:
            print(f"[upload] description update error: {e}")
            flash(f'Event created, but failed to attach images: {e}', 'error')
            # Do not return; still show success for the event itself
            return redirect(url_for('admin_events'))

    # 5) Finalize
    if uploaded_any:
        flash('Event created! ', 'success')
    else:
        flash('Event created. No images uploaded or accepted.', 'info')

    return redirect(url_for('admin_events'))

@app.post('/admin/events/<int:event_id>/toggle')
@login_required
@nocache
def admin_toggle_event(event_id):
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

@app.post('/admin/events/<int:event_id>/delete')
@login_required
def admin_delete_event(event_id):
    try:
        # Optional: fetch for storage cleanup
        ev = supabase.table('events').select('id, slug').eq('id', event_id).single().execute().data
        if not ev:
            flash('Event not found', 'error')
            return redirect(url_for('admin_events'))

        # Optional storage cleanup under slug/ if you track files or can list by folder
        # storage = supabase.storage.from_(app.config['EVENTS_BUCKET'])
        # files = storage.list(path=ev['slug'])  # if client supports listing
        # storage.remove([f"{ev['slug']}/{f['name']}" for f in files])

        # Delete event row (ensure event_images has ON DELETE CASCADE if used)
        supabase.table('events').delete().eq('id', event_id).execute()
        flash('Event deleted', 'success')
    except Exception as e:
        flash(f'Error deleting event: {e}', 'error')

    # Redirect back where the request came from
    referer = request.headers.get('Referer') or url_for('admin_events')
    return redirect(referer)

@app.post('/events/<slug>/delete')
@login_required
def admin_delete_event_by_slug(slug):
    try:
        ev = supabase.table('events').select('id, slug').eq('slug', slug).single().execute().data
        if not ev:
            flash('Event not found', 'error')
            return redirect(url_for('events_list'))

        supabase.table('events').delete().eq('id', ev['id']).execute()
        flash('Event deleted', 'success')
        return redirect(url_for('events_list'))
    except Exception as e:
        flash(f'Error deleting event: {e}', 'error')
        return redirect(url_for('event_detail', slug=slug))

from flask_login import login_required
from flask import render_template, request, redirect, url_for, flash

@app.get('/admin/events/<int:event_id>/edit')
@login_required
def admin_edit_event_form(event_id):
    ev = supabase.table('events').select('*').eq('id', event_id).single().execute().data
    if not ev:
        flash('Event not found', 'error')
        return redirect(url_for('admin_events'))
    return render_template('admin_event_edit.html', event=ev)

@app.post('/admin/events/<int:event_id>/edit')
@login_required
def admin_edit_event(event_id):
    title = (request.form.get('title') or '').strip()
    slug = (request.form.get('slug') or '').strip()
    desc = (request.form.get('description') or '').strip()
    start_at = (request.form.get('start_at') or '').strip()
    end_at = (request.form.get('end_at') or '').strip()
    is_active = True if request.form.get('is_active') == 'on' else False

    if not title:
        flash('Title is required', 'error')
        return redirect(url_for('admin_edit_event_form', event_id=event_id))

    # Optional: enforce slug uniqueness if changed
    if slug:
        existing = supabase.table('events').select('id').eq('slug', slug).neq('id', event_id).execute().data or []
        if existing:
            flash('Slug already in use', 'error')
            return redirect(url_for('admin_edit_event_form', event_id=event_id))

    update_data = {
        'title': title,
        'description': desc,
        'is_active': is_active,
    }
    if slug:
        update_data['slug'] = slug
    if start_at:
        update_data['start_at'] = start_at  # keep same storage format you already use
    if end_at:
        update_data['end_at'] = end_at

    supabase.table('events').update(update_data).eq('id', event_id).execute()
    flash('Event updated', 'success')
    return redirect(url_for('admin_events'))

@app.get('/admin/events/<int:event_id>/registrations')
@login_required
def admin_event_registrations(event_id):
    ev = supabase.table('events').select('id,title,slug').eq('id', event_id).single().execute().data
    if not ev:
        flash('Event not found', 'error')
        return redirect(url_for('admin_events'))

    regs = supabase.table('event_registrations_user') \
        .select('id,event_id,reg_number,name,email,status,registered_at') \
        .eq('event_id', event_id) \
        .order('registered_at', desc=False) \
        .execute().data or []

    return render_template('admin_event_regs.html', event=ev, regs=regs)


@app.get('/admin/events/<int:event_id>/registrations/export.csv')
@login_required
def admin_export_regs_csv(event_id):
    regs = supabase.table('event_registrations_user') \
        .select('reg_number,name,email,status,registered_at') \
        .eq('event_id', event_id) \
        .order('registered_at', desc=False) \
        .execute().data or []

    si = StringIO()
    w = csv.writer(si)
    w.writerow(['Reg Number', 'Name', 'Email', 'Status', 'Registered At'])
    for r in regs:
        w.writerow([
            r.get('reg_number',''),
            r.get('name',''),
            r.get('email',''),
            r.get('status',''),
            r.get('registered_at',''),
        ])
    resp = make_response(si.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename=registrations_event_{event_id}.csv'
    return resp

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
