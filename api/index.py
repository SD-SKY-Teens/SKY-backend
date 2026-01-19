"""
SKY-Pulse Backend API
Flask + Turso (libsql) backend for the Hours Tracker system
Designed for Vercel serverless deployment with persistent global database
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import libsql_experimental as libsql
import hashlib
import secrets
import os
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app, origins=["*"], supports_credentials=True)

# Turso Database Configuration
# Set these environment variables in Vercel:
# TURSO_DATABASE_URL: libsql://your-db-name.turso.io
# TURSO_AUTH_TOKEN: your-auth-token
TURSO_DATABASE_URL = os.environ.get('TURSO_DATABASE_URL', '')
TURSO_AUTH_TOKEN = os.environ.get('TURSO_AUTH_TOKEN', '')

# Secret key for JWT-like tokens
SECRET_KEY = os.environ.get('SECRET_KEY', 'sudharshan_kriya')

# Admin credentials (should be in environment variables in production)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '819ed74eb5d710286bbe7ba76a97d5c6da1ec01b58a10cd113608a888990fe44')


def get_db():
    """Get Turso database connection"""
    if not TURSO_DATABASE_URL or not TURSO_AUTH_TOKEN:
        raise Exception("Turso database not configured. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN environment variables.")

    conn = libsql.connect(
        database=TURSO_DATABASE_URL,
        auth_token=TURSO_AUTH_TOKEN
    )
    return conn


def student_to_dict(row):
    """Convert a student row to dictionary"""
    if row is None:
        return None
    return {
        'id': row[0],
        'name': row[1],
        'email': row[2],
        'student_key': row[3],
        'sessions': row[4],
        'total_hours': row[5],
        'created_at': row[6],
        'updated_at': row[7]
    }

def event_to_dict(row):
    """Convert an event row to dictionary"""
    if row is None:
        return None
    return {
        'id': row[0],
        'name': row[1],
        'description': row[2],
        'hours': row[3],
        'event_date': row[4],
        'registered_date': row[5],
        'created_at': row[6]
    }

def session_to_dict(row):
    """Convert a session row to dictionary"""
    if row is None:
        return None
    return {
        'id': row[0],
        'token': row[1],
        'username': row[2],
        'created_at': row[3],
        'expires_at': row[4]
    }

def log_to_dict(row):
    """Convert a security log row to dictionary"""
    if row is None:
        return None
    return {
        'id': row[0],
        'event_type': row[1],
        'details': row[2],
        'ip_address': row[3],
        'user_agent': row[4],
        'created_at': row[5]
    }


def init_db():
    """Initialize database tables"""
    conn = get_db()
    cursor = conn.cursor()

    # Students table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            student_key TEXT UNIQUE NOT NULL,
            sessions INTEGER DEFAULT 0,
            total_hours REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            hours REAL NOT NULL,
            event_date DATE NOT NULL,
            registered_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Event-Student relationship table (many-to-many)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS event_students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
            UNIQUE(event_id, student_id)
        )
    ''')

    # Sessions/tokens table for authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    ''')

    # Security log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def generate_student_key():
    """Generate a unique student key (format: SKY-XXXX-XXXX)"""
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    key = 'SKY-'
    key += ''.join(secrets.choice(chars) for _ in range(4))
    key += '-'
    key += ''.join(secrets.choice(chars) for _ in range(4))
    return key


def generate_token():
    """Generate a secure session token"""
    return secrets.token_hex(32)


def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def require_auth(f):
    """Decorator to require authentication for API endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return jsonify({'error': 'No authorization token provided'}), 401

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM sessions
            WHERE token = ? AND expires_at > datetime('now')
        ''', (token,))
        session = cursor.fetchone()
        conn.close()

        if not session:
            return jsonify({'error': 'Invalid or expired token'}), 401

        return f(*args, **kwargs)
    return decorated


# Initialize database on first request
_db_initialized = False

@app.before_request
def before_request():
    global _db_initialized
    if not _db_initialized:
        try:
            init_db()
            _db_initialized = True
        except Exception as e:
            print(f"Database initialization error: {e}")


# ============== AUTH ENDPOINTS ==============

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Admin login endpoint"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # Verify credentials
    if username != ADMIN_USERNAME or hash_password(password) != ADMIN_PASSWORD_HASH:
        # Log failed attempt
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_log (event_type, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?)
            ''', ('login_failed', f'Username: {username}', request.remote_addr, request.user_agent.string[:200]))
            conn.commit()
            conn.close()
        except:
            pass

        return jsonify({'error': 'Invalid username or password'}), 401

    # Create session token
    token = generate_token()
    expires_at = datetime.utcnow() + timedelta(hours=8)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (token, username, expires_at)
        VALUES (?, ?, ?)
    ''', (token, username, expires_at.isoformat()))
    conn.commit()
    conn.close()

    return jsonify({
        'token': token,
        'username': username,
        'expires_at': expires_at.isoformat()
    })


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Logout endpoint - invalidate token"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Logged out successfully'})


@app.route('/api/auth/verify', methods=['GET'])
@require_auth
def verify_token():
    """Verify if current token is valid"""
    return jsonify({'valid': True})


# ============== STUDENT ENDPOINTS ==============

@app.route('/api/students', methods=['GET'])
@require_auth
def get_students():
    """Get all students"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM students ORDER BY name')
    rows = cursor.fetchall()
    students = [student_to_dict(row) for row in rows]
    conn.close()

    return jsonify(students)


@app.route('/api/students', methods=['POST'])
@require_auth
def create_student():
    """Create a new student"""
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()

    if not name:
        return jsonify({'error': 'Name is required'}), 400

    # Generate unique student key
    student_key = generate_student_key()

    conn = get_db()
    cursor = conn.cursor()

    # Ensure key is unique
    while True:
        cursor.execute('SELECT id FROM students WHERE student_key = ?', (student_key,))
        if not cursor.fetchone():
            break
        student_key = generate_student_key()

    cursor.execute('''
        INSERT INTO students (name, email, student_key, sessions, total_hours)
        VALUES (?, ?, ?, 0, 0)
    ''', (name, email, student_key))
    conn.commit()

    # Get the newly created student using the unique student_key
    cursor.execute('SELECT * FROM students WHERE student_key = ?', (student_key,))
    student = student_to_dict(cursor.fetchone())
    conn.close()

    return jsonify(student), 201


@app.route('/api/students/<int:student_id>', methods=['GET'])
@require_auth
def get_student(student_id):
    """Get a single student by ID"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM students WHERE id = ?', (student_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Student not found'}), 404

    return jsonify(student_to_dict(row))


@app.route('/api/students/<int:student_id>', methods=['PUT'])
@require_auth
def update_student(student_id):
    """Update a student"""
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()

    if not name:
        return jsonify({'error': 'Name is required'}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Check if student exists first
    cursor.execute('SELECT id FROM students WHERE id = ?', (student_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Student not found'}), 404

    cursor.execute('''
        UPDATE students
        SET name = ?, email = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (name, email, student_id))

    conn.commit()
    cursor.execute('SELECT * FROM students WHERE id = ?', (student_id,))
    student = student_to_dict(cursor.fetchone())
    conn.close()

    return jsonify(student)


@app.route('/api/students/<int:student_id>', methods=['DELETE'])
@require_auth
def delete_student(student_id):
    """Delete a student"""
    conn = get_db()
    cursor = conn.cursor()

    # Check if student exists first
    cursor.execute('SELECT id FROM students WHERE id = ?', (student_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Student not found'}), 404

    # Delete from event_students first
    cursor.execute('DELETE FROM event_students WHERE student_id = ?', (student_id,))

    # Then delete the student
    cursor.execute('DELETE FROM students WHERE id = ?', (student_id,))

    conn.commit()
    conn.close()

    return jsonify({'message': 'Student deleted successfully'})


@app.route('/api/students/bulk-delete', methods=['POST'])
@require_auth
def bulk_delete_students():
    """Delete multiple students"""
    data = request.get_json()
    student_ids = data.get('ids', [])

    if not student_ids:
        return jsonify({'error': 'No student IDs provided'}), 400

    conn = get_db()
    cursor = conn.cursor()

    deleted_count = 0
    for student_id in student_ids:
        # Check if student exists
        cursor.execute('SELECT id FROM students WHERE id = ?', (student_id,))
        if cursor.fetchone():
            # Delete from event_students first
            cursor.execute('DELETE FROM event_students WHERE student_id = ?', (student_id,))
            # Then delete the student
            cursor.execute('DELETE FROM students WHERE id = ?', (student_id,))
            deleted_count += 1

    conn.commit()
    conn.close()

    return jsonify({'message': f'{deleted_count} students deleted'})


@app.route('/api/students/<int:student_id>/sessions', methods=['POST'])
@require_auth
def update_sessions(student_id):
    """Add or remove sessions from a student"""
    data = request.get_json()
    action = data.get('action', 'add')  # 'add' or 'remove'

    conn = get_db()
    cursor = conn.cursor()

    # Check if student exists first
    cursor.execute('SELECT id, sessions FROM students WHERE id = ?', (student_id,))
    student_row = cursor.fetchone()
    if not student_row:
        conn.close()
        return jsonify({'error': 'Student not found'}), 404

    current_sessions = student_row[1]

    if action == 'add':
        cursor.execute('''
            UPDATE students
            SET sessions = sessions + 1,
                total_hours = (sessions + 1) * 0.5,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (student_id,))
    elif action == 'remove':
        if current_sessions <= 0:
            conn.close()
            return jsonify({'error': 'No sessions to remove'}), 400
        cursor.execute('''
            UPDATE students
            SET sessions = sessions - 1,
                total_hours = (sessions - 1) * 0.5,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (student_id,))
    else:
        conn.close()
        return jsonify({'error': 'Invalid action'}), 400

    conn.commit()
    cursor.execute('SELECT * FROM students WHERE id = ?', (student_id,))
    student = student_to_dict(cursor.fetchone())
    conn.close()

    return jsonify(student)


# ============== EVENT ENDPOINTS ==============

@app.route('/api/events', methods=['GET'])
@require_auth
def get_events():
    """Get all events with their students"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM events ORDER BY event_date DESC')
    event_rows = cursor.fetchall()
    events = []

    for row in event_rows:
        event = event_to_dict(row)
        # Get students for this event
        cursor.execute('''
            SELECT s.id, s.name
            FROM students s
            JOIN event_students es ON s.id = es.student_id
            WHERE es.event_id = ?
        ''', (event['id'],))
        student_rows = cursor.fetchall()
        event['students'] = [{'id': s[0], 'name': s[1]} for s in student_rows]
        events.append(event)

    conn.close()
    return jsonify(events)


@app.route('/api/events', methods=['POST'])
@require_auth
def create_event():
    """Create a new event and award hours to students"""
    data = request.get_json()
    name = data.get('name', '').strip()
    description = data.get('description', '').strip()
    hours = data.get('hours', 0)
    event_date = data.get('event_date', '')
    student_ids = data.get('student_ids', [])

    if not name or not hours or not event_date:
        return jsonify({'error': 'Name, hours, and event_date are required'}), 400

    if not student_ids:
        return jsonify({'error': 'At least one student must be selected'}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Create event
    cursor.execute('''
        INSERT INTO events (name, description, hours, event_date)
        VALUES (?, ?, ?, ?)
    ''', (name, description, hours, event_date))

    # Get the event_id using last_insert_rowid()
    cursor.execute('SELECT last_insert_rowid()')
    event_id = cursor.fetchone()[0]

    # Link students to event and award hours
    sessions_to_add = round(hours / 0.5)

    for student_id in student_ids:
        cursor.execute('''
            INSERT INTO event_students (event_id, student_id)
            VALUES (?, ?)
        ''', (event_id, student_id))

        cursor.execute('''
            UPDATE students
            SET sessions = sessions + ?,
                total_hours = (sessions + ?) * 0.5,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (sessions_to_add, sessions_to_add, student_id))

    conn.commit()

    # Return created event with students
    cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
    event = event_to_dict(cursor.fetchone())
    cursor.execute('''
        SELECT s.id, s.name
        FROM students s
        JOIN event_students es ON s.id = es.student_id
        WHERE es.event_id = ?
    ''', (event_id,))
    event['students'] = [{'id': s[0], 'name': s[1]} for s in cursor.fetchall()]

    conn.close()
    return jsonify(event), 201


@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@require_auth
def delete_event(event_id):
    """Delete an event and revoke hours from students"""
    conn = get_db()
    cursor = conn.cursor()

    # Get event details first
    cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
    event_row = cursor.fetchone()

    if not event_row:
        conn.close()
        return jsonify({'error': 'Event not found'}), 404

    event = event_to_dict(event_row)
    hours = event['hours']
    sessions_to_remove = round(hours / 0.5)

    # Get students linked to this event
    cursor.execute('SELECT student_id FROM event_students WHERE event_id = ?', (event_id,))
    student_rows = cursor.fetchall()
    student_ids = [row[0] for row in student_rows]

    # Revoke hours from students
    for student_id in student_ids:
        cursor.execute('''
            UPDATE students
            SET sessions = MAX(0, sessions - ?),
                total_hours = MAX(0, sessions - ?) * 0.5,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (sessions_to_remove, sessions_to_remove, student_id))

    # Delete event_students entries
    cursor.execute('DELETE FROM event_students WHERE event_id = ?', (event_id,))

    # Delete event
    cursor.execute('DELETE FROM events WHERE id = ?', (event_id,))

    conn.commit()
    conn.close()

    return jsonify({'message': 'Event deleted successfully'})


# ============== PUBLIC STUDENT VIEW ENDPOINT ==============

@app.route('/api/public/student', methods=['POST'])
def get_student_public():
    """Public endpoint for students to view their hours"""
    data = request.get_json()
    name = data.get('name', '').strip()
    student_key = data.get('student_key', '').strip().upper()

    if not name or not student_key:
        return jsonify({'error': 'Name and student key are required'}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Find student by name (case-insensitive) and key
    cursor.execute('''
        SELECT * FROM students
        WHERE LOWER(name) = LOWER(?) AND UPPER(student_key) = ?
    ''', (name, student_key))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'Student not found or invalid key'}), 404

    student = student_to_dict(row)

    # Get events for this student
    cursor.execute('''
        SELECT e.*
        FROM events e
        JOIN event_students es ON e.id = es.event_id
        WHERE es.student_id = ?
        ORDER BY e.event_date DESC
    ''', (student['id'],))
    events = [event_to_dict(e) for e in cursor.fetchall()]

    conn.close()

    return jsonify({
        'student': {
            'name': student['name'],
            'email': student['email'],
            'sessions': student['sessions'],
            'total_hours': student['total_hours']
        },
        'events': events
    })


# ============== STATISTICS ENDPOINT ==============

@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    """Get overall statistics"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as count FROM students')
    total_students = cursor.fetchone()[0]

    cursor.execute('SELECT COALESCE(SUM(sessions), 0) as count FROM students')
    total_sessions = cursor.fetchone()[0]

    cursor.execute('SELECT COALESCE(SUM(total_hours), 0) as count FROM students')
    total_hours = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) as count FROM events')
    total_events = cursor.fetchone()[0]

    conn.close()

    return jsonify({
        'total_students': total_students,
        'total_sessions': total_sessions,
        'total_hours': total_hours,
        'total_events': total_events
    })


# ============== IMPORT/EXPORT ENDPOINTS ==============

@app.route('/api/export', methods=['GET'])
@require_auth
def export_data():
    """Export all data as JSON"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM students')
    students = [student_to_dict(row) for row in cursor.fetchall()]

    cursor.execute('SELECT * FROM events')
    event_rows = cursor.fetchall()
    events = []
    for row in event_rows:
        event = event_to_dict(row)
        cursor.execute('''
            SELECT s.id, s.name
            FROM students s
            JOIN event_students es ON s.id = es.student_id
            WHERE es.event_id = ?
        ''', (event['id'],))
        event['students'] = [{'id': s[0], 'name': s[1]} for s in cursor.fetchall()]
        events.append(event)

    conn.close()

    return jsonify({
        'students': students,
        'events': events,
        'export_date': datetime.utcnow().isoformat()
    })


@app.route('/api/import', methods=['POST'])
@require_auth
def import_data():
    """Import data from JSON (merges with existing data)"""
    data = request.get_json()
    students_data = data.get('students', [])
    events_data = data.get('events', [])

    conn = get_db()
    cursor = conn.cursor()

    imported_students = 0
    imported_events = 0

    # Import students
    for student in students_data:
        # Check if student with same key exists
        cursor.execute('SELECT id FROM students WHERE student_key = ?', (student.get('student_key', ''),))
        existing = cursor.fetchone()

        if existing:
            # Update existing student
            cursor.execute('''
                UPDATE students
                SET name = ?, email = ?, sessions = ?, total_hours = ?, updated_at = CURRENT_TIMESTAMP
                WHERE student_key = ?
            ''', (student['name'], student.get('email', ''), student.get('sessions', 0),
                  student.get('total_hours', 0), student['student_key']))
        else:
            # Insert new student
            cursor.execute('''
                INSERT INTO students (name, email, student_key, sessions, total_hours)
                VALUES (?, ?, ?, ?, ?)
            ''', (student['name'], student.get('email', ''),
                  student.get('student_key', generate_student_key()),
                  student.get('sessions', 0), student.get('total_hours', 0)))
            imported_students += 1

    conn.commit()
    conn.close()

    return jsonify({
        'message': 'Import completed',
        'imported_students': imported_students,
        'imported_events': imported_events
    })


# ============== SECURITY LOG ENDPOINTS ==============

@app.route('/api/security/log', methods=['GET'])
@require_auth
def get_security_log():
    """Get security log entries"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM security_log ORDER BY created_at DESC LIMIT 100')
    logs = [log_to_dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify(logs)


@app.route('/api/security/log', methods=['DELETE'])
@require_auth
def clear_security_log():
    """Clear security log"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM security_log')
    conn.commit()
    conn.close()

    return jsonify({'message': 'Security log cleared'})


# ============== HEALTH CHECK ==============

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    db_status = "unknown"
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })


# For local development
if __name__ == '__main__':
    app.run(debug=True, port=5000)
