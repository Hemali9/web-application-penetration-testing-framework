from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import pymysql
import re
import io
import csv

from flask import send_file

from modules import scanner  # Make sure modules/scanner.py exists

from flask import make_response
from xhtml2pdf import pisa

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# MySQL Connection
conn = pymysql.connect(host='localhost', user='root', password='', database='pentest_framework')
cursor = conn.cursor()

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'

@app.route('/')
def index():
    if 'user' in session:
        cursor.execute("SELECT * FROM targets WHERE user_id = %s", (session['user_id'],))
        targets = cursor.fetchall()
        return render_template('dashboard.html', username=session['user'], targets=targets)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not re.match(EMAIL_REGEX, email):
            flash('Invalid email format', 'error')
        else:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already exists', 'error')
            else:
                cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, password))
                conn.commit()
                flash('Signup successful! Please login.', 'success')
                return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()

        if user:
            session['user'] = user[1]  # name
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/configure', methods=['GET', 'POST'])
def configure():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        url = request.form['url']
        headers = request.form['headers']
        cookies = request.form['cookies']

        cursor.execute("INSERT INTO targets (user_id, url, headers, cookies) VALUES (%s, %s, %s, %s)",
                       (session['user_id'], url, headers, cookies))
        conn.commit()
        flash('Target configured successfully.', 'success')
        return redirect(url_for('index'))

    return render_template('configure.html')

@app.route('/target/<int:target_id>')
def view_target(target_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()

    cursor.execute("SELECT vuln_type, payload, affected_url, severity, description, recommended_fix, detected_at FROM vulnerabilities WHERE target_id = %s", (target_id,))
    findings = cursor.fetchall()

    if target:
        return render_template('view_target.html', target=target, findings=findings)
    else:
        flash('Target not found or access denied.', 'error')
        return redirect(url_for('index'))

@app.route('/scan/<int:target_id>')
def scan_target(target_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT url FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    scanner.run_all_scans(target_id, target[0])
    flash("Scan completed.", "success")
    return redirect(url_for('view_target', target_id=target_id))

@app.route('/export/csv/<int:target_id>')
def export_csv(target_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    cursor.execute("SELECT vuln_type, payload, affected_url, severity, description, recommended_fix, detected_at FROM vulnerabilities WHERE target_id = %s", (target_id,))
    findings = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Vulnerability", "Payload", "Affected URL", "Severity", "Description", "Fix", "Detected At"])
    for row in findings:
        writer.writerow(row)

    response = io.BytesIO()
    response.write(output.getvalue().encode('utf-8'))
    response.seek(0)
    output.close()

    return send_file(
        response,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'target_{target_id}_scan_results.csv'
    )

if __name__ == '__main__':
    app.run(debug=True)


@app.route('/export/pdf/<int:target_id>')
def export_pdf(target_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM targets WHERE id = %s AND user_id = %s", (target_id, session['user_id']))
    target = cursor.fetchone()
    if not target:
        flash("Target not found or access denied.", "error")
        return redirect(url_for('index'))

    cursor.execute("""
        SELECT vuln_type, payload, affected_url, severity, description, recommended_fix, detected_at 
        FROM vulnerabilities 
        WHERE target_id = %s
    """, (target_id,))
    findings = cursor.fetchall()

    rendered = render_template('report_pdf.html', target=target, findings=findings)
    response = make_response()
    pisa.CreatePDF(rendered, dest=response)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=target_{target_id}_report.pdf'
    return response


@app.route('/history')
def scan_history():
    if 'user' not in session:
        return redirect(url_for('login'))

    cursor.execute("""
        SELECT t.id, t.url, COUNT(v.id) AS total_vulns, MAX(v.detected_at) 
        FROM targets t 
        LEFT JOIN vulnerabilities v ON t.id = v.target_id 
        WHERE t.user_id = %s 
        GROUP BY t.id
        ORDER BY MAX(v.detected_at) DESC
    """, (session['user_id'],))
    history = cursor.fetchall()

    return render_template('history.html', history=history)
