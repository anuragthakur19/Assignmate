from flask import Flask, render_template, request, redirect, url_for, session, g, jsonify, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'f84e3f1c90e4a29cd9a991b8e4f7d8b3'
DATABASE = 'database.db'


# ---------------------------- DB CONNECTION ----------------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql') as f:
            db.executescript(f.read())
        db.commit()

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}


# ---------------------------- AUTH ----------------------------

@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        db = get_db()
        db.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, password))
        db.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect('/select-role')
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/select-role')
def select_role():
    return render_template('role_select.html')

@app.route('/set-role', methods=['POST'])
def set_role():
    session['role'] = request.form['role']
    return redirect('/dashboard')


# ---------------------------- DASHBOARD ----------------------------

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or 'role' not in session:
        return redirect('/login')

    db = get_db()
    user_id = session['user_id']
    role = session['role']

    if role == 'poster':
        tasks = db.execute('SELECT * FROM assignments WHERE poster_id = ?', (user_id,)).fetchall()
        enriched = []
        for task in tasks:
            count = db.execute('SELECT COUNT(*) FROM applications WHERE assignment_id = ?', (task['id'],)).fetchone()[0]
            enriched.append(dict(task, applied=count))
        return render_template('poster_dashboard.html', tasks=enriched)

    else:  # solver
        open_tasks = db.execute('SELECT * FROM assignments WHERE status = "open"').fetchall()
        assigned_tasks = db.execute('SELECT * FROM assignments WHERE selected_solver_id = ? AND status = "assigned"', (user_id,)).fetchall()
        return render_template('solver_dashboard.html', tasks=open_tasks, assigned=assigned_tasks)


# ---------------------------- ASSIGNMENTS ----------------------------

@app.route('/post', methods=['GET', 'POST'])
def post_assignment():
    if session.get('role') != 'poster':
        return redirect('/dashboard')
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        subject = request.form['subject']
        deadline = request.form['deadline']
        pages = int(request.form['pages'])
        price = pages * 10
        poster_id = session['user_id']
        db = get_db()
        db.execute('''
            INSERT INTO assignments (title, description, subject, deadline, pages, price, poster_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
        ''', (title, description, subject, deadline, pages, price, poster_id))
        db.commit()
        return redirect('/dashboard')
    return render_template('post_assignment.html')


@app.route('/assignment/<int:task_id>')
def assignment_detail(task_id):
    db = get_db()
    task = db.execute('SELECT * FROM assignments WHERE id = ?', (task_id,)).fetchone()
    role = session.get('role')
    applicants = []
    already_applied = False

    poster_profile_id = task['poster_id']
    solver_profile_id = task['selected_solver_id']

    if role == 'poster':
        applicants = db.execute('''
            SELECT u.id, u.name, u.rating FROM applications a
            JOIN users u ON a.solver_id = u.id
            WHERE a.assignment_id = ?
        ''', (task_id,)).fetchall()
    elif role == 'solver':
        existing = db.execute('SELECT 1 FROM applications WHERE assignment_id = ? AND solver_id = ?', (task_id, session['user_id'])).fetchone()
        already_applied = bool(existing)

    return render_template('assignment_detail.html', task=task, role=role,
                           applicants=applicants, already_applied=already_applied,
                           poster_profile_id=poster_profile_id,
                           solver_profile_id=solver_profile_id)


@app.route('/apply/<int:task_id>', methods=['POST'])
def apply_to_task(task_id):
    db = get_db()
    solver_id = session['user_id']
    db.execute('INSERT INTO applications (assignment_id, solver_id) VALUES (?, ?)', (task_id, solver_id))
    db.commit()
    flash('You have successfully applied to the assignment.')
    return redirect(f'/assignment/{task_id}')


@app.route('/select_solver/<int:task_id>', methods=['POST'])
def select_solver(task_id):
    solver_id = request.form['solver_id']
    db = get_db()
    db.execute('UPDATE assignments SET selected_solver_id = ?, status = "assigned" WHERE id = ?', (solver_id, task_id))
    db.execute('INSERT OR IGNORE INTO confirmations (assignment_id) VALUES (?)', (task_id,))
    db.commit()
    return redirect(f'/chat/{task_id}')


@app.route('/confirm_payment_stage/<int:task_id>', methods=['POST'])
def confirm_payment_stage(task_id):
    db = get_db()
    user_id = session['user_id']
    task = db.execute('SELECT * FROM assignments WHERE id = ?', (task_id,)).fetchone()
    is_poster = user_id == task['poster_id']
    is_solver = user_id == task['selected_solver_id']

    if is_poster:
        db.execute('UPDATE confirmations SET poster_paid = 1 WHERE assignment_id = ?', (task_id,))
    elif is_solver:
        db.execute('UPDATE confirmations SET solver_received = 1 WHERE assignment_id = ?', (task_id,))
    db.commit()

    status = db.execute('SELECT poster_paid, solver_received FROM confirmations WHERE assignment_id = ?', (task_id,)).fetchone()
    if status and status['poster_paid'] and status['solver_received']:
        db.execute('UPDATE assignments SET status = "completed" WHERE id = ?', (task_id,))
        db.commit()
        flash('Payment confirmed by both parties. Assignment marked completed.')
    else:
        flash('Your confirmation is recorded. Waiting for the other party.')

    return redirect(f'/chat/{task_id}')


@app.route('/rate_solver', methods=['POST'])
def rate_solver():
    db = get_db()
    rating = int(request.form['rating'])
    comment = request.form.get('comment', '')
    task_id = int(request.form['task_id'])
    task = db.execute('SELECT * FROM assignments WHERE id = ?', (task_id,)).fetchone()
    if not task:
        return jsonify({'success': False, 'error': 'Assignment not found'}), 404
    solver_id = task['selected_solver_id']
    from_user = session['user_id']

    db.execute('''
        INSERT INTO ratings (from_user, to_user, assignment_id, score, comment)
        VALUES (?, ?, ?, ?, ?)
    ''', (from_user, solver_id, task_id, rating, comment))

    # Update average rating
    ratings = db.execute('SELECT AVG(score) FROM ratings WHERE to_user = ?', (solver_id,)).fetchone()[0]
    db.execute('UPDATE users SET rating = ? WHERE id = ?', (ratings, solver_id))
    db.commit()

    flash('Solver rated successfully!')
    return redirect('/dashboard')


@app.route('/delete/<int:task_id>', methods=['POST'])
def delete_assignment(task_id):
    if 'user_id' not in session or session.get('role') != 'poster':
        return redirect('/login')
    db = get_db()
    task = db.execute('SELECT * FROM assignments WHERE id = ?', (task_id,)).fetchone()
    if task and task['poster_id'] == session['user_id']:
        db.execute('DELETE FROM assignments WHERE id = ?', (task_id,))
        db.execute('DELETE FROM applications WHERE assignment_id = ?', (task_id,))
        db.execute('DELETE FROM messages WHERE assignment_id = ?', (task_id,))
        db.commit()
    return redirect('/dashboard')


# ---------------------------- CHAT ----------------------------

@app.route('/chat/<int:task_id>', methods=['GET', 'POST'])
def chat(task_id):
    db = get_db()
    if request.method == 'POST':
        message = request.form['message']
        sender_id = session['user_id']
        db.execute('INSERT INTO messages (assignment_id, sender_id, content) VALUES (?, ?, ?)', (task_id, sender_id, message))
        db.commit()
        return redirect(f'/chat/{task_id}')
    task = db.execute('SELECT * FROM assignments WHERE id = ?', (task_id,)).fetchone()
    messages = db.execute('''
        SELECT m.content, m.sender_id, m.timestamp, u.name AS sender, 
            CASE 
                WHEN u.id = a.poster_id THEN 'poster'
                WHEN u.id = a.selected_solver_id THEN 'solver'
                ELSE 'unknown'
            END AS role
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        JOIN assignments a ON m.assignment_id = a.id
        WHERE m.assignment_id = ?
        ORDER BY m.timestamp ASC
    ''', (task_id,)).fetchall()
    return render_template('chat.html', task=task, messages=messages, user_id=session['user_id'])

# ---------------------------- ADMIN ----------------------------

ADMIN_EMAIL = 'adminmail123@gmail.com'
ADMIN_PASSWORD = 'examplepassword'

@app.route('/administrator')
def admin_login():
    return render_template('admin_login.html')


@app.route('/admin-login', methods=['POST'])
def admin_authenticate():
    email = request.form['email']
    password = request.form['password']
    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        session['admin'] = True
        return redirect('/admin-panel')
    else:
        return render_template('admin_login.html', error='Invalid credentials')


@app.route('/admin-panel')
def admin_panel():
    if not session.get('admin'):
        return redirect('/administrator')

    db = get_db()

    stats = {
        'user_count': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'assignment_count': db.execute('SELECT COUNT(*) FROM assignments').fetchone()[0],
        'completed_count': db.execute('SELECT COUNT(*) FROM assignments WHERE status = "completed"').fetchone()[0],
        'message_count': db.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
    }

    users = db.execute('SELECT id, name, email, rating FROM users').fetchall()
    assignments = db.execute('''
        SELECT a.id, a.title, a.status, u.name AS poster_name, 
               s.name AS solver_name,
               (SELECT COUNT(*) FROM applications WHERE assignment_id = a.id) AS applicant_count
        FROM assignments a
        LEFT JOIN users u ON a.poster_id = u.id
        LEFT JOIN users s ON a.selected_solver_id = s.id
    ''').fetchall()

    messages = db.execute('SELECT id, assignment_id, sender_id, content FROM messages ORDER BY id DESC LIMIT 50').fetchall()

    return render_template('admin_panel.html', stats=stats, users=users, assignments=assignments, messages=messages)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('admin'):
        return redirect('/administrator')

    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.execute('DELETE FROM assignments WHERE poster_id = ?', (user_id,))
    db.execute('DELETE FROM assignments WHERE selected_solver_id = ?', (user_id,))
    db.execute('DELETE FROM applications WHERE solver_id = ?', (user_id,))
    db.execute('DELETE FROM messages WHERE sender_id = ?', (user_id,))
    db.commit()
    return redirect('/admin-panel')


@app.route('/admin/delete_assignment/<int:assignment_id>', methods=['POST'])
def admin_delete_assignment(assignment_id):
    if not session.get('admin'):
        return redirect('/administrator')

    db = get_db()
    db.execute('DELETE FROM assignments WHERE id = ?', (assignment_id,))
    db.execute('DELETE FROM applications WHERE assignment_id = ?', (assignment_id,))
    db.execute('DELETE FROM messages WHERE assignment_id = ?', (assignment_id,))
    db.execute('DELETE FROM confirmations WHERE assignment_id = ?', (assignment_id,))
    db.commit()
    return redirect('/admin-panel')


@app.route('/admin/delete_message/<int:message_id>', methods=['POST'])
def admin_delete_message(message_id):
    if not session.get('admin'):
        return redirect('/administrator')

    db = get_db()
    db.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    db.commit()
    return redirect('/admin-panel')


# ---------------------------- ADMIN EXTRA ROUTES ----------------------------

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if not session.get('admin'):
        return redirect('/administrator')

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        rating = float(request.form['rating'])
        db.execute('UPDATE users SET name = ?, email = ?, rating = ? WHERE id = ?', (name, email, rating, user_id))
        db.commit()
        flash('User details updated.')
        return redirect('/admin-panel')

    return render_template('admin_edit_user.html', user=user)


@app.route('/admin/search/users', methods=['GET'])
def admin_search_users():
    if not session.get('admin'):
        return redirect('/administrator')

    keyword = request.args.get('q', '').strip()
    db = get_db()
    users = db.execute('''
        SELECT id, name, email, rating 
        FROM users 
        WHERE name LIKE ? OR email LIKE ?
    ''', (f'%{keyword}%', f'%{keyword}%')).fetchall()

    stats = {
        'user_count': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'assignment_count': db.execute('SELECT COUNT(*) FROM assignments').fetchone()[0],
        'completed_count': db.execute('SELECT COUNT(*) FROM assignments WHERE status = "completed"').fetchone()[0],
        'message_count': db.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
    }

    return render_template('admin_panel.html', stats=stats, users=users, assignments=[], messages=[])


@app.route('/admin/filter/assignments')
def admin_filter_assignments():
    if not session.get('admin'):
        return redirect('/administrator')

    status = request.args.get('status', '').strip()
    db = get_db()
    assignments = db.execute('''
        SELECT a.id, a.title, a.status, u.name AS poster_name, 
               s.name AS solver_name,
               (SELECT COUNT(*) FROM applications WHERE assignment_id = a.id) AS applicant_count
        FROM assignments a
        LEFT JOIN users u ON a.poster_id = u.id
        LEFT JOIN users s ON a.selected_solver_id = s.id
        WHERE a.status = ?
    ''', (status,)).fetchall()

    stats = {
        'user_count': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'assignment_count': db.execute('SELECT COUNT(*) FROM assignments').fetchone()[0],
        'completed_count': db.execute('SELECT COUNT(*) FROM assignments WHERE status = "completed"').fetchone()[0],
        'message_count': db.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
    }

    return render_template('admin_panel.html', stats=stats, users=[], assignments=assignments, messages=[])




# ---------------------------- USER PROFILE UPDATE ----------------------------

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        if password:
            hashed_pw = generate_password_hash(password)
            db.execute('UPDATE users SET name = ?, password = ? WHERE id = ?', (name, hashed_pw, session['user_id']))
        else:
            db.execute('UPDATE users SET name = ? WHERE id = ?', (name, session['user_id']))
        db.commit()
        flash('Profile updated successfully!')
        return redirect('/edit_profile')

    return render_template('edit_profile.html', user=user)


@app.route('/profile')
def my_profile_redirect():
    if 'user_id' not in session:
        return redirect('/login')
    return redirect(url_for('view_profile', user_id=session['user_id']))


# ---------------------------- MY APPLICATIONS (SOLVER VIEW) ----------------------------

@app.route('/my_applications')
def my_applications():
    if 'user_id' not in session or session.get('role') != 'solver':
        return redirect('/login')
    db = get_db()
    tasks = db.execute('''
        SELECT a.* FROM assignments a
        JOIN applications app ON a.id = app.assignment_id
        WHERE app.solver_id = ?
    ''', (session['user_id'],)).fetchall()
    return render_template('my_applications.html', applications=tasks)


# ---------------------------- ASSIGNMENT PRIVATE NOTES ----------------------------

@app.route('/assignment/<int:task_id>/notes', methods=['GET', 'POST'])
def assignment_notes(task_id):
    if 'user_id' not in session:
        return redirect('/login')

    db = get_db()
    task = db.execute('SELECT * FROM assignments WHERE id = ?', (task_id,)).fetchone()
    if not task:
        return "Assignment not found", 404

    role = session['role']
    user_id = session['user_id']

    if (role == 'poster' and task['poster_id'] != user_id) or (role == 'solver' and task['selected_solver_id'] != user_id):
        return "Unauthorized", 403

    note_row = db.execute('SELECT * FROM notes WHERE assignment_id = ? AND user_id = ?', (task_id, user_id)).fetchone()
    current_note = note_row['note'] if note_row else ''

    if request.method == 'POST':
        note = request.form['note']
        if note_row:
            db.execute('UPDATE notes SET note = ? WHERE assignment_id = ? AND user_id = ?', (note, task_id, user_id))
        else:
            db.execute('INSERT INTO notes (assignment_id, user_id, note) VALUES (?, ?, ?)', (task_id, user_id, note))
        db.commit()
        flash('Note saved successfully!')
        return redirect(f'/assignment/{task_id}/notes')

    return render_template('assignment_notes.html', task=task, note=current_note)


#-------------------------Rating-----------------------------#

@app.route('/rate_poster', methods=['POST'])
def rate_poster():
    db = get_db()
    rating = int(request.form['rating'])
    task_id = int(request.form['task_id'])
    comment = request.form.get('comment')

    task = db.execute('SELECT * FROM assignments WHERE id = ?', (task_id,)).fetchone()
    if not task:
        return jsonify({'success': False, 'error': 'Assignment not found'}), 404

    poster_id = task['poster_id']
    from_user = session['user_id']

    db.execute('''
        INSERT INTO ratings (from_user, to_user, assignment_id, score, comment)
        VALUES (?, ?, ?, ?, ?)
    ''', (from_user, poster_id, task_id, rating, comment))

    # Update average rating of the poster
    ratings = db.execute('SELECT AVG(score) FROM ratings WHERE to_user = ?', (poster_id,)).fetchone()[0]
    db.execute('UPDATE users SET rating = ? WHERE id = ?', (ratings, poster_id))
    db.commit()

    flash('Poster rated successfully!')
    return redirect('/dashboard')



# ---------------------------- PUBLIC PROFILE ----------------------------

@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    posted = db.execute('SELECT * FROM assignments WHERE poster_id = ?', (user_id,)).fetchall()
    solved = db.execute('SELECT * FROM assignments WHERE selected_solver_id = ?', (user_id,)).fetchall()
    return render_template('public_profile.html', user=user,
                           posted=posted if posted else None,
                           solved=solved if solved else None)


# ---------------------------- RUN ----------------------------

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
