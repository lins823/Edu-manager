EXCELLENCE ACADEMY - SCHOOL MANAGEMENT SYSTEM

REQUIREMENTS
Python 3.9 or newer (https://www.python.org/downloads/). On Windows, tick
"Add Python to PATH" during install.

START THE SYSTEM
Windows : double-click START.bat
Mac/Linux: run  ./START.sh   (or: python3 app.py)
Then open   http://localhost:5000   in your browser.
Keep the black terminal window open while you use the system.
Logins are in CREDENTIALS.txt.

IF LOGIN DOES NOT WORK
1. Look at the terminal window. A failed login prints a line such as
   "[LOGIN] failed: wrong password for 'admin'" or an error message.
2. Open http://localhost:5000/health  - it should show {"status":"ok"}.
3. Reset the database to the default accounts:
       python app.py --reset-db
   (an old school.db is kept as school.db.old-<date>)
4. Use the exact username and password from CREDENTIALS.txt.
5. Browser must accept cookies for localhost.
Send me the text in the terminal window if it still fails.

FILES
app.py            the application
school.db         database (created automatically if missing)
templates/        HTML pages (login, base, and 7 dashboards)
static/           style.css, main.js, uploads/ (school logo)
requirements.txt  Flask and Werkzeug

BEFORE REAL USE
- Change all default passwords.
- Back up school.db regularly (copy the file).
- Do not use the built-in server on the public internet. Use a proper
  server such as gunicorn behind HTTPS, and set a SECRET_KEY
  environment variable.
