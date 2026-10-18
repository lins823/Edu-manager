"""
Excellence Academy — School Management System
Single-file Flask backend using sqlite3 only (no ORM needed)
Run: python app.py
"""
import sqlite3, os, re
from datetime import datetime, date, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g)

# ── App ──────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Works with the normal layout (templates/ and static/ folders) AND with a flat
# folder where every file was downloaded into one place.
app = Flask(__name__, static_folder=None)
from jinja2 import ChoiceLoader, FileSystemLoader
app.jinja_loader = ChoiceLoader([FileSystemLoader(os.path.join(BASE_DIR, "templates")),
                                 FileSystemLoader(BASE_DIR)])

def serve_static(filename):
    from flask import send_from_directory, abort
    for folder, name in ((os.path.join(BASE_DIR, "static"), filename),
                         (BASE_DIR, os.path.basename(filename))):
        if os.path.isfile(os.path.join(folder, name)):
            return send_from_directory(folder, name)
    abort(404)
app.add_url_rule("/static/<path:filename>", endpoint="static", view_func=serve_static)
DB = os.path.join(BASE_DIR, "school.db")
UPLOADS = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOADS, exist_ok=True)

def _load_secret():
    """Use SECRET_KEY env var, else a key persisted next to the app (survives restarts)."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE_DIR, "secret.key")
    if not os.path.exists(path):
        import secrets
        with open(path, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()

app.secret_key = _load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=4 * 1024 * 1024)

def hash_pw(pw):
    # pbkdf2 works on every Python build (scrypt needs OpenSSL support)
    return generate_password_hash(pw, method="pbkdf2:sha256")

# ── DB helpers ────────────────────────────────────────────────────
def get_db():
    d = getattr(g, "_db", None)
    if d is None:
        d = g._db = sqlite3.connect(DB)
        d.row_factory = sqlite3.Row
        d.execute("PRAGMA foreign_keys=ON")
    return d

@app.teardown_appcontext
def close_db(_): 
    d = getattr(g, "_db", None)
    if d: d.close()

def q(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows

def w(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid

# ── Auth helpers ──────────────────────────────────────────────────
def login_req(f):
    @wraps(f)
    def wrap(*a, **kw):
        if "uid" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrap

def role_req(*roles):
    def deco(f):
        @wraps(f)
        def wrap(*a, **kw):
            if session.get("role") not in roles:
                flash("Access denied.", "error")
                return redirect(url_for("dashboard"))
            return f(*a, **kw)
        return wrap
    return deco

# ── Context helpers ───────────────────────────────────────────────
def get_settings():
    row = q("SELECT * FROM school_settings LIMIT 1", one=True)
    return dict(row) if row else {"school_name":"Excellence Academy","school_motto":"Knowledge is Power","logo_path":""}

def get_term():
    return q("SELECT * FROM terms WHERE is_current=1 LIMIT 1", one=True)

def grade(marks, total=100):
    p = marks / total * 100
    return "A" if p>=80 else "B" if p>=70 else "C" if p>=60 else "D" if p>=50 else "F"

@app.context_processor
def ctx():
    return dict(settings=get_settings(), term=get_term(), session=session)

# ── INDEX ─────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))

# ── LOGIN / LOGOUT ────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if "uid" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = q("""
            SELECT u.id, u.username, u.password_hash, r.name as role
            FROM users u JOIN roles r ON r.id=u.role_id
            WHERE u.username=? AND u.is_active=1
        """, (username,), one=True)
        ok = False
        if user:
            try:
                ok = check_password_hash(user["password_hash"], password)
            except Exception as exc:          # unsupported hash type on this Python
                print(f"[LOGIN] hash check error for '{username}': {exc}")
        if not user:
            print(f"[LOGIN] failed: no active user named '{username}'")
        elif not ok:
            print(f"[LOGIN] failed: wrong password for '{username}'")
        if user and ok:
            session.clear()
            session.permanent = False
            session["uid"]      = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            w("UPDATE users SET last_login=? WHERE id=?",
              (datetime.now().isoformat(), user["id"]))
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_req
def dashboard():
    r = session["role"]
    targets = {
        "admin":           "admin_dash",
        "principal":       "principal_dash",
        "deputy_principal":"deputy_dash",
        "teacher":         "teacher_dash",
        "boarding_master": "boarding_dash",
        "bursar":          "bursar_dash",
        "parent":          "parent_dash",
    }
    return redirect(url_for(targets[r])) if r in targets else redirect(url_for("login"))

# ════════════════════════════════════════════════════════════════
# ADMIN
# ════════════════════════════════════════════════════════════════
@app.route("/admin")
@login_req
@role_req("admin")
def admin_dash():
    users   = q("SELECT u.*,r.name as role_name FROM users u JOIN roles r ON r.id=u.role_id ORDER BY r.name,u.username")
    roles   = q("SELECT * FROM roles ORDER BY name")
    terms   = q("SELECT * FROM terms ORDER BY id DESC")
    classes = q("""
        SELECT c.id as cid, c.name as cname, s.id as sid, s.name as sname,
               e.first_name||' '||e.last_name as teacher_name
        FROM classes c LEFT JOIN streams s ON s.class_id=c.id
        LEFT JOIN teachers t ON t.id=s.class_teacher_id
        LEFT JOIN employees e ON e.id=t.employee_id
        ORDER BY c.name, s.name
    """)
    hostels = q("SELECT * FROM hostels ORDER BY gender,name")
    teachers = q("SELECT t.id, e.first_name||' '||e.last_name as name FROM teachers t JOIN employees e ON e.id=t.employee_id")
    return render_template("admin.html",
        users=users, roles=roles, terms=terms,
        classes=classes, hostels=hostels, teachers=teachers)

@app.route("/admin/create_user", methods=["POST"])
@login_req
@role_req("admin")
def admin_create_user():
    f = request.form
    if q("SELECT id FROM users WHERE username=?", (f["username"],), one=True):
        flash("Username already taken.", "error")
        return redirect(url_for("admin_dash"))
    role_name = q("SELECT name FROM roles WHERE id=?", (f["role_id"],), one=True)["name"]
    uid = w("INSERT INTO users(username,password_hash,role_id) VALUES(?,?,?)",
            (f["username"], hash_pw(f["password"]), f["role_id"]))
    if role_name != "parent":
        eid = w("INSERT INTO employees(user_id,first_name,last_name,email,phone) VALUES(?,?,?,?,?)",
                (uid, f.get("first_name",""), f.get("last_name",""), f.get("email",""), f.get("phone","")))
        if role_name in ("teacher","boarding_master"):
            w("INSERT INTO teachers(employee_id,subject_specialization) VALUES(?,?)",
              (eid, f.get("subject","")))
    else:
        w("INSERT INTO parents(user_id,first_name,last_name,phone,email,relationship) VALUES(?,?,?,?,?,?)",
          (uid, f.get("first_name",""), f.get("last_name",""), f.get("phone",""), f.get("email",""), f.get("relationship","guardian")))
    flash(f"User '{f['username']}' created.", "success")
    return redirect(url_for("admin_dash"))

@app.route("/admin/reset_password", methods=["POST"])
@login_req
@role_req("admin")
def admin_reset_pw():
    w("UPDATE users SET password_hash=? WHERE id=?",
      (hash_pw(request.form["new_password"]), request.form["user_id"]))
    flash("Password reset.", "success")
    return redirect(url_for("admin_dash"))

@app.route("/admin/create_term", methods=["POST"])
@login_req
@role_req("admin")
def admin_create_term():
    w("UPDATE terms SET is_current=0")
    w("INSERT INTO terms(name,academic_year,opening_date,start_date,end_date,is_current) VALUES(?,?,?,?,?,1)",
      (request.form["name"], request.form["academic_year"],
       request.form["opening_date"], request.form["start_date"], request.form["end_date"]))
    flash("Term created and set as current.", "success")
    return redirect(url_for("admin_dash"))

@app.route("/admin/create_class", methods=["POST"])
@login_req
@role_req("admin")
def admin_create_class():
    f = request.form
    row = q("SELECT id FROM classes WHERE name=?", (f["class_name"],), one=True)
    cid = row["id"] if row else w("INSERT INTO classes(name,level) VALUES(?,?)", (f["class_name"], f.get("level") or None))
    w("INSERT OR IGNORE INTO streams(class_id,name,class_teacher_id) VALUES(?,?,?)",
      (cid, f["stream_name"], f.get("teacher_id") or None))
    flash("Class/stream created.", "success")
    return redirect(url_for("admin_dash"))

@app.route("/admin/branding", methods=["POST"])
@login_req
@role_req("admin")
def admin_branding():
    f    = request.form
    file = request.files.get("logo")
    logo = None
    if file and file.filename:
        ext = file.filename.rsplit(".",1)[-1].lower()
        if ext in ("png","jpg","jpeg","gif"):
            fn = secure_filename(file.filename)
            path = os.path.join(UPLOADS, fn)
            file.save(path)
            logo = path.replace("\\","/")
    if logo:
        w("UPDATE school_settings SET school_name=?,school_motto=?,logo_path=?",
          (f["school_name"], f["school_motto"], logo))
    else:
        w("UPDATE school_settings SET school_name=?,school_motto=?",
          (f["school_name"], f["school_motto"]))
    flash("Branding updated.", "success")
    return redirect(url_for("admin_dash"))

# ════════════════════════════════════════════════════════════════
# PRINCIPAL
# ════════════════════════════════════════════════════════════════
@app.route("/principal")
@login_req
@role_req("principal")
def principal_dash():
    term = get_term()
    tid  = term["id"] if term else 0
    fin = q("""
        SELECT c.name||' '||s.name AS cls,
               COUNT(DISTINCT st.id) AS cnt,
               COALESCE(SUM(fr.total_amount),0) AS total,
               COALESCE(SUM(fr.amount_paid),0)  AS paid,
               COALESCE(SUM(fr.balance),0)       AS bal
        FROM streams s JOIN classes c ON c.id=s.class_id
        LEFT JOIN students st ON st.stream_id=s.id
        LEFT JOIN financial_records fr ON fr.student_id=st.id AND fr.term_id=?
        GROUP BY s.id ORDER BY c.name,s.name
    """, (tid,))
    acad = q("""
        SELECT c.name||' '||s.name AS cls, e.subject,
               ROUND(AVG(r.marks_obtained),1) AS avg
        FROM exams e JOIN streams s ON s.id=e.stream_id
        JOIN classes c ON c.id=s.class_id
        JOIN results r ON r.exam_id=e.id
        WHERE e.term_id=?
        GROUP BY s.id,e.subject ORDER BY c.name,e.subject
    """, (tid,))
    staff = q("""
        SELECT e.first_name||' '||e.last_name AS name,
               r.name AS role, e.email, e.phone
        FROM employees e JOIN users u ON u.id=e.user_id
        JOIN roles r ON r.id=u.role_id ORDER BY r.name,e.last_name
    """)
    disc_count = q("SELECT COUNT(*) AS n FROM discipline_records WHERE term_id=?", (tid,), one=True)["n"]
    search = None
    sq = request.args.get("q","").strip()
    if sq:
        search = q("""
            SELECT st.*, c.name||' '||s.name AS cls
            FROM students st LEFT JOIN streams s ON s.id=st.stream_id
            LEFT JOIN classes c ON c.id=s.class_id
            WHERE st.admission_number=? OR st.first_name LIKE ? OR st.last_name LIKE ?
        """, (sq, f"%{sq}%", f"%{sq}%"))
    return render_template("principal.html",
        fin=fin, acad=acad, staff=staff, disc_count=disc_count, search=search)

@app.route("/principal/reactivate/<int:sid>")
@login_req
@role_req("principal")
def principal_reactivate(sid):
    w("UPDATE students SET status='active' WHERE id=?", (sid,))
    flash("Student reactivated.", "success")
    return redirect(url_for("principal_dash"))

# ════════════════════════════════════════════════════════════════
# DEPUTY PRINCIPAL
# ════════════════════════════════════════════════════════════════
@app.route("/deputy")
@login_req
@role_req("deputy_principal")
def deputy_dash():
    term = get_term()
    tid  = term["id"] if term else 0
    students = q("""
        SELECT st.*, c.name||' '||s.name AS cls
        FROM students st LEFT JOIN streams s ON s.id=st.stream_id
        LEFT JOIN classes c ON c.id=s.class_id ORDER BY c.name,st.last_name
    """)
    records = q("""
        SELECT d.*, st.first_name||' '||st.last_name AS sname,
               st.admission_number, c.name||' '||s.name AS cls
        FROM discipline_records d JOIN students st ON st.id=d.student_id
        LEFT JOIN streams s ON s.id=st.stream_id
        LEFT JOIN classes c ON c.id=s.class_id
        WHERE d.term_id=? ORDER BY d.report_date DESC
    """, (tid,))
    suspended = [s for s in students if s["status"]=="suspended"]
    search = None
    sq = request.args.get("q","").strip()
    if sq:
        search = q("""
            SELECT st.*, c.name||' '||s.name AS cls
            FROM students st LEFT JOIN streams s ON s.id=st.stream_id
            LEFT JOIN classes c ON c.id=s.class_id
            WHERE st.admission_number=? OR st.first_name LIKE ? OR st.last_name LIKE ?
        """, (sq, f"%{sq}%", f"%{sq}%"))
    return render_template("deputy.html",
        students=students, records=records, suspended=suspended, search=search)

@app.route("/deputy/add_discipline", methods=["POST"])
@login_req
@role_req("deputy_principal")
def deputy_add_disc():
    term = get_term()
    if not term:
        flash("No active term.", "error")
        return redirect(url_for("deputy_dash"))
    sid = int(request.form["student_id"])
    w("""INSERT INTO discipline_records
       (student_id,term_id,offense,description,action_taken,severity,reported_by,report_date)
       VALUES(?,?,?,?,?,?,?,?)""",
      (sid, term["id"], request.form["offense"],
       request.form.get("description",""), request.form.get("action_taken",""),
       request.form.get("severity","minor"), session["uid"], date.today().isoformat()))
    # Auto-suspend at 3
    cnt = q("SELECT COUNT(*) AS n FROM discipline_records WHERE student_id=? AND term_id=?",
            (sid,term["id"]), one=True)["n"]
    if cnt >= 3:
        w("UPDATE students SET status='suspended' WHERE id=?", (sid,))
        flash("⚠️ Student has been automatically suspended (3 offences).", "warning")
    else:
        flash("Discipline record saved.", "success")
    return redirect(url_for("deputy_dash"))

# ════════════════════════════════════════════════════════════════
# TEACHER
# ════════════════════════════════════════════════════════════════
def teacher_stream():
    return q("""
        SELECT t.id AS tid, s.id AS sid, c.name||' '||s.name AS cls,
               c.name AS cname, s.name AS sname
        FROM teachers t JOIN employees e ON e.id=t.employee_id
        JOIN streams s ON s.class_teacher_id=t.id
        JOIN classes c ON c.id=s.class_id
        WHERE e.user_id=? LIMIT 1
    """, (session["uid"],), one=True)

@app.route("/teacher")
@login_req
@role_req("teacher")
def teacher_dash():
    term   = get_term()
    tid    = term["id"] if term else 0
    stream = teacher_stream()
    students, exams, results, fees, reqs = [], [], [], [], []
    if stream:
        sid = stream["sid"]
        students = q("""
            SELECT st.*, h.name AS hostel
            FROM students st LEFT JOIN hostel_allocations ha ON ha.student_id=st.id
            LEFT JOIN hostels h ON h.id=ha.hostel_id
            WHERE st.stream_id=? ORDER BY st.last_name
        """, (sid,))
        exams = q("SELECT * FROM exams WHERE stream_id=? AND term_id=? ORDER BY exam_date DESC", (sid, tid))
        results = q("""
            SELECT r.*, st.first_name||' '||st.last_name AS sname,
                   e.name AS ename, e.subject, e.total_marks
            FROM results r JOIN students st ON st.id=r.student_id
            JOIN exams e ON e.id=r.exam_id
            WHERE e.stream_id=? AND e.term_id=? ORDER BY e.exam_date DESC,st.last_name
        """, (sid, tid))
        fees = q("""
            SELECT st.first_name||' '||st.last_name AS sname,
                   st.admission_number,
                   fr.total_amount, fr.amount_paid, fr.balance
            FROM students st LEFT JOIN financial_records fr ON fr.student_id=st.id AND fr.term_id=?
            WHERE st.stream_id=? ORDER BY st.last_name
        """, (tid, sid))
        reqs = q("""
            SELECT ar.*, st.first_name||' '||st.last_name AS sname
            FROM add_remove_requests ar LEFT JOIN students st ON st.id=ar.student_id
            WHERE ar.requested_by=? ORDER BY ar.request_date DESC
        """, (session["uid"],))
    search = None
    sq = request.args.get("q","").strip()
    if sq and stream:
        search = q("""
            SELECT st.* FROM students st
            WHERE st.stream_id=? AND (st.admission_number=? OR st.first_name LIKE ? OR st.last_name LIKE ?)
        """, (stream["sid"], sq, f"%{sq}%", f"%{sq}%"))
    return render_template("teacher.html",
        stream=stream, students=students, exams=exams,
        results=results, fees=fees, reqs=reqs,
        search=search, today=date.today().isoformat())

def apply_first_week_rule(term, stream_id):
    """Students with no 'present' mark in the first 7 days of term become inactive
    (checked once the first week is over)."""
    opening = date.fromisoformat(term["opening_date"])
    week_end = opening + timedelta(days=7)
    if date.today() <= week_end:
        return 0
    rows = q("SELECT id FROM students WHERE stream_id=? AND status='active'", (stream_id,))
    n = 0
    for st in rows:
        seen = q("""SELECT 1 FROM attendance WHERE student_id=? AND term_id=?
                    AND status='present' AND date>=? AND date<=? LIMIT 1""",
                 (st["id"], term["id"], opening.isoformat(), week_end.isoformat()), one=True)
        if not seen:
            w("UPDATE students SET status='inactive' WHERE id=?", (st["id"],))
            n += 1
    return n

@app.route("/teacher/attendance", methods=["POST"])
@login_req
@role_req("teacher")
def teacher_attendance():
    term = get_term()
    if not term:
        flash("No active term.", "error")
        return redirect(url_for("teacher_dash"))
    att_date = request.form["att_date"]
    sids     = request.form.getlist("sids")
    statuses = request.form.getlist("statuses")
    db = get_db()
    for sid, status in zip(sids, statuses):
        db.execute("""
            INSERT INTO attendance(student_id,term_id,date,status,marked_by)
            VALUES(?,?,?,?,?)
            ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status
        """, (sid, term["id"], att_date, status, session["uid"]))
    db.commit()
    stream = teacher_stream()
    deactivated = apply_first_week_rule(term, stream["sid"]) if stream else 0
    if deactivated:
        flash(f"Attendance saved. {deactivated} student(s) had no first-week attendance and are now inactive.", "warning")
    else:
        flash("Attendance saved.", "success")
    return redirect(url_for("teacher_dash"))

@app.route("/teacher/create_exam", methods=["POST"])
@login_req
@role_req("teacher")
def teacher_create_exam():
    term = get_term()
    stream = teacher_stream()
    if not term or not stream:
        flash("No active term or class assigned.", "error")
        return redirect(url_for("teacher_dash"))
    w("INSERT INTO exams(name,term_id,stream_id,subject,total_marks,exam_date,created_by) VALUES(?,?,?,?,?,?,?)",
      (request.form["name"], term["id"], stream["sid"],
       request.form["subject"], int(request.form.get("total_marks",100)),
       request.form.get("exam_date") or None, session["uid"]))
    flash("Exam created.", "success")
    return redirect(url_for("teacher_dash"))

@app.route("/teacher/save_marks", methods=["POST"])
@login_req
@role_req("teacher")
def teacher_save_marks():
    exam_id = request.form["exam_id"]
    exam    = q("SELECT * FROM exams WHERE id=?", (exam_id,), one=True)
    sids    = request.form.getlist("sids")
    marks   = request.form.getlist("marks")
    db = get_db()
    for sid, m in zip(sids, marks):
        if not m.strip(): continue
        mf = float(m)
        g  = grade(mf, exam["total_marks"])
        db.execute("""
            INSERT INTO results(student_id,exam_id,marks_obtained,grade,entered_by)
            VALUES(?,?,?,?,?)
            ON CONFLICT(student_id,exam_id) DO UPDATE SET marks_obtained=excluded.marks_obtained,grade=excluded.grade
        """, (sid, exam_id, mf, g, session["uid"]))
    db.commit()
    flash("Marks saved.", "success")
    return redirect(url_for("teacher_dash"))

@app.route("/teacher/request", methods=["POST"])
@login_req
@role_req("teacher")
def teacher_request():
    stream = teacher_stream()
    raw = (request.form.get("student_id") or "").strip()
    reason = request.form.get("reason", "")
    student_id = None
    if raw:
        row = q("SELECT id FROM students WHERE id=? OR admission_number=?",
                (raw if raw.isdigit() else -1, raw), one=True)
        if row:
            student_id = row["id"]
        else:                       # unknown admission number: keep it in the reason text
            reason = f"[Adm. no. {raw}] {reason}"
    w("""INSERT INTO add_remove_requests(request_type,student_id,stream_id,reason,requested_by)
       VALUES(?,?,?,?,?)""",
      (request.form["request_type"], student_id,
       stream["sid"] if stream else None, reason, session["uid"]))
    flash("Request submitted to Bursar.", "success")
    return redirect(url_for("teacher_dash"))

# ════════════════════════════════════════════════════════════════
# BOARDING MASTER
# ════════════════════════════════════════════════════════════════
@app.route("/boarding")
@login_req
@role_req("boarding_master")
def boarding_dash():
    hostels  = q("SELECT * FROM hostels ORDER BY gender,name")
    boarders = q("""
        SELECT st.*, h.name AS hostel, h.id AS hid,
               c.name||' '||s.name AS cls
        FROM students st LEFT JOIN hostel_allocations ha ON ha.student_id=st.id
        LEFT JOIN hostels h ON h.id=ha.hostel_id
        LEFT JOIN streams s ON s.id=st.stream_id
        LEFT JOIN classes c ON c.id=s.class_id
        ORDER BY h.name,st.last_name
    """)
    search = None
    sq = request.args.get("q","").strip()
    if sq:
        search = q("""
            SELECT st.*, h.name AS hostel, c.name||' '||s.name AS cls
            FROM students st LEFT JOIN hostel_allocations ha ON ha.student_id=st.id
            LEFT JOIN hostels h ON h.id=ha.hostel_id
            LEFT JOIN streams s ON s.id=st.stream_id
            LEFT JOIN classes c ON c.id=s.class_id
            WHERE st.admission_number=? OR st.first_name LIKE ? OR st.last_name LIKE ?
        """, (sq, f"%{sq}%", f"%{sq}%"))
    return render_template("boarding.html",
        hostels=hostels, boarders=boarders, search=search)

@app.route("/boarding/relocate", methods=["POST"])
@login_req
@role_req("boarding_master")
def boarding_relocate():
    sid     = request.form["student_id"]
    new_hid = request.form["new_hostel_id"]
    old = q("SELECT hostel_id FROM hostel_allocations WHERE student_id=?", (sid,), one=True)
    if old:
        w("UPDATE hostels SET current_occupancy=MAX(0,current_occupancy-1) WHERE id=?", (old["hostel_id"],))
        w("UPDATE hostel_allocations SET hostel_id=?,allocated_date=? WHERE student_id=?",
          (new_hid, date.today().isoformat(), sid))
    else:
        w("INSERT INTO hostel_allocations(student_id,hostel_id,allocated_date) VALUES(?,?,?)",
          (sid, new_hid, date.today().isoformat()))
    w("UPDATE hostels SET current_occupancy=current_occupancy+1 WHERE id=?", (new_hid,))
    flash("Student relocated.", "success")
    return redirect(url_for("boarding_dash"))

# ════════════════════════════════════════════════════════════════
# BURSAR
# ════════════════════════════════════════════════════════════════
@app.route("/bursar")
@login_req
@role_req("bursar")
def bursar_dash():
    term    = get_term()
    tid     = term["id"] if term else 0
    streams = q("SELECT s.id, c.name||' '||s.name AS full FROM streams s JOIN classes c ON c.id=s.class_id ORDER BY c.name,s.name")
    hostels = q("SELECT * FROM hostels ORDER BY gender,name")
    fees    = q("""
        SELECT st.id, st.first_name||' '||st.last_name AS sname,
               st.admission_number, st.status,
               c.name||' '||s.name AS cls,
               fr.total_amount, fr.amount_paid, fr.balance
        FROM students st LEFT JOIN streams s ON s.id=st.stream_id
        LEFT JOIN classes c ON c.id=s.class_id
        LEFT JOIN financial_records fr ON fr.student_id=st.id AND fr.term_id=?
        ORDER BY c.name,s.name,st.last_name
    """, (tid,))
    reqs = q("""
        SELECT ar.*, st.first_name||' '||st.last_name AS sname,
               e.first_name||' '||e.last_name AS rname
        FROM add_remove_requests ar LEFT JOIN students st ON st.id=ar.student_id
        JOIN users u ON u.id=ar.requested_by
        JOIN employees e ON e.user_id=u.id
        WHERE ar.status='pending' ORDER BY ar.request_date DESC
    """)
    search = None
    sq = request.args.get("q","").strip()
    if sq:
        search = q("""
            SELECT st.*, c.name||' '||s.name AS cls,
                   fr.total_amount, fr.amount_paid, fr.balance
            FROM students st LEFT JOIN streams s ON s.id=st.stream_id
            LEFT JOIN classes c ON c.id=s.class_id
            LEFT JOIN financial_records fr ON fr.student_id=st.id AND fr.term_id=?
            WHERE st.admission_number=? OR st.first_name LIKE ? OR st.last_name LIKE ?
        """, (tid, sq, f"%{sq}%", f"%{sq}%"))
    return render_template("bursar.html",
        fees=fees, reqs=reqs, streams=streams, hostels=hostels, search=search)

@app.route("/bursar/register", methods=["POST"])
@login_req
@role_req("bursar")
def bursar_register():
    f    = request.form
    term = get_term()
    # Validate unique admission number
    if q("SELECT id FROM students WHERE admission_number=?", (f["admission_number"],), one=True):
        flash("Admission number already exists.", "error")
        return redirect(url_for("bursar_dash"))
    gender = f["gender"]
    sid = w("""INSERT INTO students
        (admission_number,first_name,middle_name,last_name,date_of_birth,
         gender,stream_id,blood_group,health_condition,special_diet,disability,created_by)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (f["admission_number"].strip(), f["first_name"].strip(),
         f.get("middle_name","").strip(), f["last_name"].strip(),
         f.get("dob","") or None, gender,
         f.get("stream_id") or None,
         f.get("blood_group") or None,
         f.get("health_condition","").strip() or None,
         f.get("special_diet","").strip() or None,
         f.get("disability","").strip() or None,
         session["uid"]))

    def add_parent(prefix, primary):
        fn = f.get(f"{prefix}_fn","").strip()
        ln = f.get(f"{prefix}_ln","").strip()
        ph = f.get(f"{prefix}_phone","").strip()
        un = f.get(f"{prefix}_user","").strip()
        pw = f.get(f"{prefix}_pass","").strip()
        if not fn or not ph or not un or not pw:
            return
        ex = q("SELECT id FROM users WHERE username=?", (un,), one=True)
        if ex:
            puid = ex["id"]
        else:
            role_row = q("SELECT id FROM roles WHERE name='parent'", one=True)
            puid = w("INSERT INTO users(username,password_hash,role_id) VALUES(?,?,?)",
                     (un, hash_pw(pw), role_row["id"]))
            w("""INSERT INTO parents(user_id,first_name,last_name,phone,email,relationship)
               VALUES(?,?,?,?,?,?)""",
              (puid, fn, ln, ph, f.get(f"{prefix}_email",""), f.get(f"{prefix}_rel","guardian")))
        pr = q("SELECT id FROM parents WHERE user_id=?", (puid,), one=True)
        if pr:
            w("INSERT OR IGNORE INTO student_parent_relationship(student_id,parent_id,is_primary) VALUES(?,?,?)",
              (sid, pr["id"], 1 if primary else 0))

    add_parent("p1", True)
    if f.get("p2_fn","").strip():
        add_parent("p2", False)

    # Hostel
    hid = f.get("hostel_id") or None
    if not hid:
        row = q("SELECT id FROM hostels WHERE gender=? AND current_occupancy<capacity ORDER BY current_occupancy LIMIT 1", (gender,), one=True)
        hid = row["id"] if row else None
    if hid:
        w("INSERT OR IGNORE INTO hostel_allocations(student_id,hostel_id,allocated_date) VALUES(?,?,?)",
          (sid, hid, date.today().isoformat()))
        w("UPDATE hostels SET current_occupancy=current_occupancy+1 WHERE id=?", (hid,))

    # Initial fees
    if term and f.get("total_fees","").strip():
        total = float(f["total_fees"])
        paid  = float(f.get("initial_paid","0") or 0)
        frid  = w("INSERT INTO financial_records(student_id,term_id,total_amount,amount_paid,balance) VALUES(?,?,?,?,?)",
                  (sid, term["id"], total, paid, total-paid))
        if paid > 0:
            w("INSERT INTO payments(financial_record_id,amount,payment_method,recorded_by) VALUES(?,?,?,?)",
              (frid, paid, f.get("pay_method","cash"), session["uid"]))

    flash(f"Student {f['first_name']} {f['last_name']} registered.", "success")
    return redirect(url_for("bursar_dash"))

@app.route("/bursar/update_fees", methods=["POST"])
@login_req
@role_req("bursar")
def bursar_update_fees():
    f    = request.form
    term = get_term()
    if not term:
        flash("No active term.", "error")
        return redirect(url_for("bursar_dash"))
    sid   = f["student_id"]
    total = float(f["total_amount"])
    pay   = float(f.get("payment","0") or 0)
    ex = q("SELECT * FROM financial_records WHERE student_id=? AND term_id=?", (sid, term["id"]), one=True)
    if ex:
        new_paid = ex["amount_paid"] + pay
        w("UPDATE financial_records SET total_amount=?,amount_paid=?,balance=?,updated_by=? WHERE id=?",
          (total, new_paid, total-new_paid, session["uid"], ex["id"]))
        frid = ex["id"]
    else:
        frid = w("INSERT INTO financial_records(student_id,term_id,total_amount,amount_paid,balance,updated_by) VALUES(?,?,?,?,?,?)",
                 (sid, term["id"], total, pay, total-pay, session["uid"]))
    if pay > 0:
        w("INSERT INTO payments(financial_record_id,amount,payment_method,receipt_number,recorded_by) VALUES(?,?,?,?,?)",
          (frid, pay, f.get("pay_method","cash"), f.get("receipt",""), session["uid"]))
    flash("Fee record updated.", "success")
    return redirect(url_for("bursar_dash"))

@app.route("/bursar/review/<int:rid>/<action>")
@login_req
@role_req("bursar")
def bursar_review(rid, action):
    if action not in ("approved","rejected"):
        return redirect(url_for("bursar_dash"))
    req = q("SELECT * FROM add_remove_requests WHERE id=?", (rid,), one=True)
    if req and action=="approved" and req["request_type"]=="remove" and req["student_id"]:
        w("UPDATE students SET stream_id=NULL WHERE id=?", (req["student_id"],))
    w("UPDATE add_remove_requests SET status=?,reviewed_by=?,review_date=? WHERE id=?",
      (action, session["uid"], datetime.now().isoformat(), rid))
    flash(f"Request {action}.", "success")
    return redirect(url_for("bursar_dash"))

# ════════════════════════════════════════════════════════════════
# PARENT
# ════════════════════════════════════════════════════════════════
@app.route("/parent")
@login_req
@role_req("parent")
def parent_dash():
    par = q("SELECT * FROM parents WHERE user_id=?", (session["uid"],), one=True)
    if not par:
        flash("Parent record not found. Contact admin.", "error")
        return redirect(url_for("login"))
    term = get_term()
    tid  = term["id"] if term else 0
    children_raw = q("""
        SELECT st.*, c.name||' '||s.name AS cls, h.name AS hostel
        FROM student_parent_relationship spr
        JOIN students st ON st.id=spr.student_id
        LEFT JOIN streams s ON s.id=st.stream_id
        LEFT JOIN classes c ON c.id=s.class_id
        LEFT JOIN hostel_allocations ha ON ha.student_id=st.id
        LEFT JOIN hostels h ON h.id=ha.hostel_id
        WHERE spr.parent_id=? ORDER BY spr.is_primary DESC,st.first_name
    """, (par["id"],))
    children = []
    for ch in children_raw:
        csid = ch["id"]
        results = q("""
            SELECT r.*,e.name AS ename,e.subject,e.total_marks,e.exam_date
            FROM results r JOIN exams e ON e.id=r.exam_id
            WHERE r.student_id=? ORDER BY e.exam_date DESC
        """, (csid,))
        fees = q("""
            SELECT fr.*,t.name AS tname FROM financial_records fr
            JOIN terms t ON t.id=fr.term_id
            WHERE fr.student_id=? ORDER BY fr.id DESC
        """, (csid,))
        disc = q("""
            SELECT d.*,t.name AS tname FROM discipline_records d
            JOIN terms t ON t.id=d.term_id
            WHERE d.student_id=? ORDER BY d.report_date DESC
        """, (csid,))
        att = q("SELECT status,COUNT(*) AS n FROM attendance WHERE student_id=? AND term_id=? GROUP BY status",
                (csid, tid))
        att_map   = {r["status"]: r["n"] for r in att}
        total_d   = sum(att_map.values())
        present_d = att_map.get("present", 0)
        att_pct   = round(present_d/total_d*100,1) if total_d else 0
        children.append(dict(ch) | {
            "results": results, "fees": fees,
            "disc": disc, "att_pct": att_pct,
            "present_d": present_d, "total_d": total_d
        })
    return render_template("parent.html", par=par, children=children)

# ════════════════════════════════════════════════════════════════
# SCHEMA + SEED
# ════════════════════════════════════════════════════════════════
SCHEMA = """
CREATE TABLE IF NOT EXISTS roles(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS school_settings(id INTEGER PRIMARY KEY,school_name TEXT DEFAULT 'Excellence Academy',school_motto TEXT DEFAULT 'Knowledge is Power',logo_path TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role_id INTEGER NOT NULL REFERENCES roles(id),is_active INTEGER DEFAULT 1,last_login TEXT);
CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),first_name TEXT NOT NULL,last_name TEXT NOT NULL,email TEXT,phone TEXT,hire_date TEXT DEFAULT CURRENT_DATE);
CREATE TABLE IF NOT EXISTS teachers(id INTEGER PRIMARY KEY AUTOINCREMENT,employee_id INTEGER UNIQUE NOT NULL REFERENCES employees(id),subject_specialization TEXT);
CREATE TABLE IF NOT EXISTS parents(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),first_name TEXT NOT NULL,last_name TEXT NOT NULL,phone TEXT NOT NULL,email TEXT,relationship TEXT,address TEXT,occupation TEXT);
CREATE TABLE IF NOT EXISTS terms(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,academic_year TEXT NOT NULL,opening_date TEXT NOT NULL,start_date TEXT NOT NULL,end_date TEXT NOT NULL,is_current INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS classes(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL,level INTEGER);
CREATE TABLE IF NOT EXISTS streams(id INTEGER PRIMARY KEY AUTOINCREMENT,class_id INTEGER NOT NULL REFERENCES classes(id),name TEXT NOT NULL,class_teacher_id INTEGER REFERENCES teachers(id),UNIQUE(class_id,name));
CREATE TABLE IF NOT EXISTS hostels(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL,capacity INTEGER NOT NULL,current_occupancy INTEGER DEFAULT 0,gender TEXT CHECK(gender IN('male','female'))NOT NULL);
CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY AUTOINCREMENT,admission_number TEXT UNIQUE NOT NULL,first_name TEXT NOT NULL,middle_name TEXT,last_name TEXT NOT NULL,date_of_birth TEXT,gender TEXT CHECK(gender IN('male','female'))NOT NULL,stream_id INTEGER REFERENCES streams(id),blood_group TEXT,health_condition TEXT,special_diet TEXT,disability TEXT,status TEXT DEFAULT 'active',admission_date TEXT DEFAULT CURRENT_DATE,created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS student_parent_relationship(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id),parent_id INTEGER NOT NULL REFERENCES parents(id),is_primary INTEGER DEFAULT 0,UNIQUE(student_id,parent_id));
CREATE TABLE IF NOT EXISTS hostel_allocations(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER UNIQUE NOT NULL REFERENCES students(id),hostel_id INTEGER NOT NULL REFERENCES hostels(id),allocated_date TEXT DEFAULT CURRENT_DATE);
CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id),term_id INTEGER NOT NULL REFERENCES terms(id),date TEXT NOT NULL,status TEXT NOT NULL,marked_by INTEGER REFERENCES users(id),UNIQUE(student_id,date));
CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,term_id INTEGER NOT NULL REFERENCES terms(id),stream_id INTEGER NOT NULL REFERENCES streams(id),subject TEXT NOT NULL,total_marks INTEGER DEFAULT 100,exam_date TEXT,created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id),exam_id INTEGER NOT NULL REFERENCES exams(id),marks_obtained REAL NOT NULL,grade TEXT,entered_by INTEGER REFERENCES users(id),entered_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(student_id,exam_id));
CREATE TABLE IF NOT EXISTS financial_records(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id),term_id INTEGER NOT NULL REFERENCES terms(id),total_amount REAL NOT NULL,amount_paid REAL DEFAULT 0,balance REAL,fee_reset INTEGER DEFAULT 0,updated_by INTEGER REFERENCES users(id),UNIQUE(student_id,term_id));
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT,financial_record_id INTEGER NOT NULL REFERENCES financial_records(id),amount REAL NOT NULL,payment_date TEXT DEFAULT CURRENT_DATE,payment_method TEXT,receipt_number TEXT,recorded_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS discipline_records(id INTEGER PRIMARY KEY AUTOINCREMENT,student_id INTEGER NOT NULL REFERENCES students(id),term_id INTEGER NOT NULL REFERENCES terms(id),offense TEXT NOT NULL,description TEXT,action_taken TEXT,severity TEXT,reported_by INTEGER NOT NULL REFERENCES users(id),report_date TEXT DEFAULT CURRENT_DATE);
CREATE TABLE IF NOT EXISTS add_remove_requests(id INTEGER PRIMARY KEY AUTOINCREMENT,request_type TEXT NOT NULL,student_id INTEGER REFERENCES students(id),stream_id INTEGER REFERENCES streams(id),reason TEXT,requested_by INTEGER NOT NULL REFERENCES users(id),request_date TEXT DEFAULT CURRENT_TIMESTAMP,status TEXT DEFAULT 'pending',reviewed_by INTEGER REFERENCES users(id),review_date TEXT);
"""

def seed():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)

    for r in ["admin","principal","deputy_principal","teacher","boarding_master","bursar","parent"]:
        db.execute("INSERT OR IGNORE INTO roles(name) VALUES(?)", (r,))
    db.execute("INSERT OR IGNORE INTO school_settings(id,school_name,school_motto,logo_path) VALUES(1,'Excellence Academy','Knowledge is Power','')")
    _t = date.today()
    _open = _t - timedelta(days=2)             # term opened 2 days ago: first week still running
    _term_no = 1 if _t.month <= 4 else (2 if _t.month <= 8 else 3)
    db.execute("INSERT OR IGNORE INTO terms(id,name,academic_year,opening_date,start_date,end_date,is_current) VALUES(1,?,?,?,?,?,1)",
               (f"Term {_term_no} {_t.year}", str(_t.year), _open.isoformat(), _open.isoformat(),
                (_open + timedelta(days=90)).isoformat()))
    db.commit()

    def rid(name): return db.execute("SELECT id FROM roles WHERE name=?", (name,)).fetchone()["id"]
    def add_user(uname, pw, role):
        row = db.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
        if row: return row["id"]
        db.execute("INSERT INTO users(username,password_hash,role_id) VALUES(?,?,?)",
                   (uname, hash_pw(pw), rid(role)))
        db.commit()
        return db.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()["id"]
    def add_emp(uid, fn, ln, email, phone):
        row = db.execute("SELECT id FROM employees WHERE user_id=?", (uid,)).fetchone()
        if row: return row["id"]
        db.execute("INSERT INTO employees(user_id,first_name,last_name,email,phone) VALUES(?,?,?,?,?)",(uid,fn,ln,email,phone))
        db.commit()
        return db.execute("SELECT id FROM employees WHERE user_id=?", (uid,)).fetchone()["id"]
    def add_teacher(eid, subj=""):
        row = db.execute("SELECT id FROM teachers WHERE employee_id=?", (eid,)).fetchone()
        if row: return row["id"]
        db.execute("INSERT INTO teachers(employee_id,subject_specialization) VALUES(?,?)", (eid, subj))
        db.commit()
        return db.execute("SELECT id FROM teachers WHERE employee_id=?", (eid,)).fetchone()["id"]

    admin_uid = add_user("admin","Admin@2025","admin")
    add_emp(admin_uid,"System","Administrator","admin@school.ac","0700000001")

    p_uid = add_user("principal","Principal@2025","principal")
    add_emp(p_uid,"Dr. Grace","Mwangi","principal@school.ac","0700000002")

    d_uid = add_user("deputy","Deputy@2025","deputy_principal")
    add_emp(d_uid,"Mr. James","Otieno","deputy@school.ac","0700000003")

    t1_uid = add_user("teacher1","Teacher@2025","teacher")
    t1_eid = add_emp(t1_uid,"Ms. Alice","Wambua","alice@school.ac","0700000004")
    t1_id  = add_teacher(t1_eid,"Mathematics")

    t2_uid = add_user("teacher2","Teacher@2025","teacher")
    t2_eid = add_emp(t2_uid,"Mr. Brian","Kamau","brian@school.ac","0700000005")
    t2_id  = add_teacher(t2_eid,"English")

    bm_uid = add_user("boarding","Boarding@2025","boarding_master")
    bm_eid = add_emp(bm_uid,"Mrs. Susan","Njoroge","boarding@school.ac","0700000006")
    add_teacher(bm_eid,"")

    b_uid = add_user("bursar","Bursar@2025","bursar")
    add_emp(b_uid,"Mr. Peter","Kariuki","bursar@school.ac","0700000007")

    # Classes
    for name, lvl in [("Form 1",1),("Form 2",2),("Form 3",3),("Form 4",4)]:
        db.execute("INSERT OR IGNORE INTO classes(name,level) VALUES(?,?)", (name, lvl))
    db.commit()
    f1 = db.execute("SELECT id FROM classes WHERE name='Form 1'").fetchone()["id"]
    f2 = db.execute("SELECT id FROM classes WHERE name='Form 2'").fetchone()["id"]
    db.execute("INSERT OR IGNORE INTO streams(class_id,name,class_teacher_id) VALUES(?,?,?)", (f1,"A",t1_id))
    db.execute("INSERT OR IGNORE INTO streams(class_id,name,class_teacher_id) VALUES(?,?,?)", (f1,"B",t2_id))
    db.execute("INSERT OR IGNORE INTO streams(class_id,name,class_teacher_id) VALUES(?,?,?)", (f2,"A",None))
    db.commit()
    s1 = db.execute("SELECT id FROM streams WHERE class_id=? AND name='A'", (f1,)).fetchone()["id"]

    # Hostels: 4 boys @40, 2 girls @70
    for h in [("Lions",40,"male"),("Tigers",40,"male"),("Eagles",40,"male"),("Hawks",40,"male"),
              ("Roses",70,"female"),("Lilies",70,"female")]:
        db.execute("INSERT OR IGNORE INTO hostels(name,capacity,gender) VALUES(?,?,?)", h)
    db.commit()
    boys_h  = db.execute("SELECT id FROM hostels WHERE name='Lions'").fetchone()["id"]
    girls_h = db.execute("SELECT id FROM hostels WHERE name='Roses'").fetchone()["id"]

    # Parents
    par1_uid = add_user("parent1","Parent@2025","parent")
    db.execute("INSERT OR IGNORE INTO parents(user_id,first_name,last_name,phone,email,relationship) VALUES(?,?,?,?,?,?)",
               (par1_uid,"Mr. David","Kamau","0722000001","d.kamau@email.com","father"))
    db.commit()
    par1 = db.execute("SELECT id FROM parents WHERE user_id=?", (par1_uid,)).fetchone()["id"]

    par2_uid = add_user("parent2","Parent@2025","parent")
    db.execute("INSERT OR IGNORE INTO parents(user_id,first_name,last_name,phone,email,relationship) VALUES(?,?,?,?,?,?)",
               (par2_uid,"Mrs. Jane","Odhiambo","0722000002","j.odhiambo@email.com","mother"))
    db.commit()
    par2 = db.execute("SELECT id FROM parents WHERE user_id=?", (par2_uid,)).fetchone()["id"]

    # Students
    seed_students = [
        ("ADM2025001","Alice","","Kamau","2009-03-15","female",s1,"B+",None,None,None),
        ("ADM2025002","Brian","K.","Otieno","2009-07-22","male",s1,"O+",None,"Vegetarian",None),
        ("ADM2025003","Carol","","Wanjiku","2010-01-10","female",s1,"A+","Asthma",None,None),
        ("ADM2025004","Daniel","","Mwangi","2009-11-05","male",s1,"B-",None,None,None),
        ("ADM2025005","Eve","","Achieng","2010-04-18","female",s1,"O-",None,None,"Dyslexia"),
    ]
    for adm,fn,mn,ln,dob,gen,stm,bg,hc,sd,dis in seed_students:
        if not db.execute("SELECT id FROM students WHERE admission_number=?", (adm,)).fetchone():
            db.execute("""INSERT INTO students(admission_number,first_name,middle_name,last_name,
                date_of_birth,gender,stream_id,blood_group,health_condition,special_diet,disability)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (adm,fn,mn,ln,dob,gen,stm,bg,hc,sd,dis))
    db.commit()

    for adm, pid, prim in [("ADM2025001",par1,1),("ADM2025002",par1,1),
                            ("ADM2025003",par2,1),("ADM2025004",par2,1),
                            ("ADM2025001",par2,0)]:
        s = db.execute("SELECT id FROM students WHERE admission_number=?", (adm,)).fetchone()
        if s:
            db.execute("INSERT OR IGNORE INTO student_parent_relationship(student_id,parent_id,is_primary) VALUES(?,?,?)",
                       (s["id"], pid, prim))
    db.commit()

    term_id = db.execute("SELECT id FROM terms WHERE is_current=1").fetchone()["id"]
    for adm in ["ADM2025001","ADM2025002","ADM2025003","ADM2025004","ADM2025005"]:
        s = db.execute("SELECT * FROM students WHERE admission_number=?", (adm,)).fetchone()
        if not s: continue
        hid = girls_h if s["gender"]=="female" else boys_h
        db.execute("INSERT OR IGNORE INTO hostel_allocations(student_id,hostel_id) VALUES(?,?)", (s["id"],hid))
        db.execute("INSERT OR IGNORE INTO financial_records(student_id,term_id,total_amount,amount_paid,balance) VALUES(?,?,?,?,?)",
                   (s["id"],term_id,45000,20000,25000))
    db.commit()

    # Fix occupancy
    db.execute("UPDATE hostels SET current_occupancy=(SELECT COUNT(*) FROM hostel_allocations WHERE hostel_id=hostels.id)")
    db.commit()

    # Sample exam
    if not db.execute("SELECT id FROM exams WHERE name='Mid-Term Mathematics'").fetchone():
        db.execute("INSERT INTO exams(name,term_id,stream_id,subject,total_marks,exam_date,created_by) VALUES(?,?,?,?,?,?,?)",
                   ("Mid-Term Mathematics",term_id,s1,"Mathematics",100,(date.today() - timedelta(days=1)).isoformat(),t1_uid))
        db.commit()
        eid = db.execute("SELECT id FROM exams WHERE name='Mid-Term Mathematics'").fetchone()["id"]
        for adm, m in [("ADM2025001",78),("ADM2025002",85),("ADM2025003",62),("ADM2025004",91),("ADM2025005",55)]:
            s = db.execute("SELECT id FROM students WHERE admission_number=?", (adm,)).fetchone()
            if s:
                db.execute("INSERT OR IGNORE INTO results(student_id,exam_id,marks_obtained,grade,entered_by) VALUES(?,?,?,?,?)",
                           (s["id"],eid,m,grade(m),t1_uid))
        db.commit()

    # Sample discipline
    dep = db.execute("SELECT id FROM users WHERE username='deputy'").fetchone()["id"]
    s = db.execute("SELECT id FROM students WHERE admission_number='ADM2025002'").fetchone()
    if s:
        db.execute("INSERT OR IGNORE INTO discipline_records(student_id,term_id,offense,severity,reported_by) VALUES(?,?,?,?,?)",
                   (s["id"],term_id,"Late to class","minor",dep))
    db.commit()
    db.close()
    print("Database ready.")

REQUIRED_TABLES = {"roles", "users", "students", "terms", "school_settings",
                   "employees", "teachers", "parents", "streams", "classes", "hostels"}

def db_is_healthy():
    """True if school.db exists, has this app's tables and at least one user."""
    if not os.path.exists(DB):
        return False
    try:
        con = sqlite3.connect(DB)
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not REQUIRED_TABLES <= names:
            con.close(); return False
        cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
        n = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        con.close()
        return {"username", "password_hash", "role_id", "is_active"} <= cols and n > 0
    except Exception:
        return False

def init_db(force=False):
    """Create/repair the database. An incompatible old school.db is kept as a backup."""
    if force or not db_is_healthy():
        if os.path.exists(DB):
            backup = DB + ".old-" + datetime.now().strftime("%Y%m%d-%H%M%S")
            os.replace(DB, backup)
            print(f"[DB] Existing school.db was not usable - moved to {os.path.basename(backup)}")
        seed()
        print("[DB] Fresh database created with default accounts (see CREDENTIALS.txt)")

def check_files():
    """Tell the user clearly if files are missing instead of showing a Jinja error."""
    need = ["login.html", "base.html", "admin.html", "principal.html", "deputy.html",
            "teacher.html", "boarding.html", "bursar.html", "parent.html"]
    missing = [n for n in need if not any(os.path.isfile(os.path.join(d, n)) for d in
               (os.path.join(BASE_DIR, "templates"), BASE_DIR))]
    if missing:
        print("\n" + "=" * 62)
        print(" MISSING TEMPLATE FILES: " + ", ".join(missing))
        print(" App folder: " + BASE_DIR)
        print(" Put the .html files in a folder named 'templates' next to app.py,")
        print(" or unzip excellence-academy-sms.zip and run it from there.")
        print("=" * 62 + "\n")

check_files()
init_db()          # runs on import, so it also works with `flask run` / gunicorn

@app.route("/health")
def health():
    n = q("SELECT COUNT(*) AS n FROM users", one=True)["n"]
    return {"status": "ok", "users": n, "database": os.path.basename(DB)}

if __name__ == "__main__":
    import sys
    if "--reset-db" in sys.argv:
        init_db(force=True)
        print("Database reset. Start the app again with: python app.py")
        sys.exit(0)
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"\n  Excellence Academy SMS running at  http://localhost:{port}\n")
    app.run(debug=debug, host="0.0.0.0", port=port)
