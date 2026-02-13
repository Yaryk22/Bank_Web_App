import random
import secrets
from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_file, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from db import init_db, get_db, log_action, backup_database
from functools import wraps
from datetime import timedelta, datetime
import re
from io import BytesIO
import qrcode
import base64

app = Flask(__name__)

# ========== ПОКРАЩЕНА БЕЗПЕКА ==========
app.secret_key = secrets.token_hex(32)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = False  # True при HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Security Headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com https://bank.gov.ua; img-src 'self' data:;"
    return response

# Rate Limiting
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 хвилин

# ========== ІНІЦІАЛІЗАЦІЯ БД ==========
init_db()

with app.app_context():
    db = get_db()
    
    # Додаткові таблиці для розширеного функціоналу
    db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('Поповнення', 'Зняття', 'Переказ')),
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (card_id) REFERENCES cards (id) ON DELETE CASCADE
        )
    """)
    
    db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info' CHECK(type IN ('success', 'error', 'warning', 'info')),
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    db.commit()
    print("✅ Кристал Банк: Система готова до роботи")

# ========== HELPER FUNCTIONS ==========
def sanitize_input(text):
    """Очищення введених даних"""
    if not text:
        return ""
    return re.sub(r'[<>"\']', '', str(text).strip())

def validate_phone(phone):
    """Валідація номера телефону"""
    pattern = r'^\+(?!7)[0-9]{7,15}$'
    return re.match(pattern, phone) is not None

def validate_name(name):
    """Валідація імені"""
    pattern = r'^[a-zA-Zа-яА-ЯіІїЇєЄґҐ\s\'\-\.]+$'
    return re.match(pattern, name) is not None and len(name) >= 2

def check_rate_limit(ip):
    """Перевірка обмеження спроб входу"""
    if ip in login_attempts:
        attempts, last_attempt = login_attempts[ip]
        if datetime.now().timestamp() - last_attempt < LOCKOUT_TIME:
            if attempts >= MAX_LOGIN_ATTEMPTS:
                return False
    return True

def record_login_attempt(ip, success=False):
    """Запис спроби входу"""
    if ip not in login_attempts:
        login_attempts[ip] = [0, datetime.now().timestamp()]
    
    if success:
        login_attempts.pop(ip, None)
    else:
        attempts, _ = login_attempts[ip]
        login_attempts[ip] = [attempts + 1, datetime.now().timestamp()]

def create_notification(user, message, notification_type='info'):
    """Створення нотифікації"""
    db = get_db()
    db.execute(
        "INSERT INTO notifications (user, message, type) VALUES (?, ?, ?)",
        (user, message, notification_type)
    )
    db.commit()

# ========== DECORATOR ==========
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            flash("Будь ласка, увійдіть в систему", "error")
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    log_action(session.get('user', 'anonymous'), f'500 Error: {str(e)}', ip_address=request.remote_addr)
    return render_template('500.html'), 500

# ========== AUTHENTICATION ==========
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        
        if not check_rate_limit(ip):
            remaining_time = int(LOCKOUT_TIME / 60)
            flash(f"⚠️ Забагато невдалих спроб. Спробуйте через {remaining_time} хвилин", "error")
            return render_template("login.html")
        
        username = sanitize_input(request.form.get("username"))
        password = request.form.get("password")

        if not username or not password:
            flash("Заповніть всі поля", "error")
            return render_template("login.html")

        db = get_db()
        user = db.execute(
            "SELECT * FROM employees WHERE username = ? AND is_active = 1",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["login_time"] = datetime.now().isoformat()
            
            # Оновлення last_login
            db.execute(
                "UPDATE employees SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user["id"],)
            )
            db.commit()
            
            record_login_attempt(ip, success=True)
            log_action(username, "Успішний вхід в систему", ip_address=ip)
            create_notification(username, "Ви увійшли в систему", "success")
            
            flash(f"Вітаємо, {username}!", "success")
            return redirect("/clients")

        record_login_attempt(ip, success=False)
        log_action(username or "невідомий", "Невдала спроба входу", ip_address=ip)
        flash("Невірний логін або пароль", "error")

    return render_template("login.html")

@app.route("/logout")
def logout():
    user = session.get("user")
    if user:
        log_action(user, "Вихід з системи", ip_address=request.remote_addr)
    session.clear()
    flash("Ви успішно вийшли з системи", "info")
    return redirect("/login")

@app.route("/")
def index():
    if "user" in session:
        return redirect("/clients")
    return redirect("/login")

# ========== CLIENTS ==========
@app.route("/clients")
@login_required
def clients_page():
    search_query = sanitize_input(request.args.get('search', ''))
    client_type = request.args.get('type', '')
    
    db = get_db()
    
    if search_query or client_type:
        query = "SELECT * FROM clients WHERE 1=1"
        params = []
        
        if search_query:
            query += " AND (name LIKE ? OR phone LIKE ?)"
            params.extend([f"%{search_query}%", f"%{search_query}%"])
        
        if client_type and client_type in ['Фізична особа', 'Юридична особа']:
            query += " AND type = ?"
            params.append(client_type)
        
        query += " ORDER BY id DESC"
        clients = db.execute(query, params).fetchall()
    else:
        clients = db.execute("SELECT * FROM clients ORDER BY id DESC").fetchall()

    # Статистика
    stats = {
        "total_clients": db.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
        "physical_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Фізична особа'").fetchone()[0],
        "legal_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Юридична особа'").fetchone()[0],
        "new_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],
        "active_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Активна'").fetchone()[0],
        "total_balance": db.execute("SELECT SUM(balance) FROM cards WHERE currency='UAH'").fetchone()[0] or 0
    }

    return render_template("clients.html", 
                         clients=clients, 
                         stats=stats, 
                         search_query=search_query,
                         client_type=client_type)

@app.route("/add-client", methods=["GET", "POST"])
@login_required
def add_client():
    if request.method == "POST":
        name = sanitize_input(request.form.get("name"))
        phone = sanitize_input(request.form.get("phone"))
        client_type = sanitize_input(request.form.get("type"))
        
        # Валідація
        errors = []
        if not validate_name(name):
            errors.append("ПІБ має містити мінімум 2 символи і лише літери")
        
        if not validate_phone(phone):
            errors.append("Невірний формат телефону. Формат: +380XXXXXXXXX")
        
        if client_type not in ["Фізична особа", "Юридична особа"]:
            errors.append("Невірний тип клієнта")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("add_clients.html")
        
        db = get_db()
        
        # Перевірка дублікату телефону
        existing = db.execute("SELECT id FROM clients WHERE phone = ?", (phone,)).fetchone()
        if existing:
            flash(f"❌ Клієнт з телефоном {phone} вже існує в системі", "error")
            return render_template("add_clients.html")
        
        try:
            cursor = db.execute(
                "INSERT INTO clients (name, phone, type) VALUES (?, ?, ?)",
                (name, phone, client_type)
            )
            db.commit()
            
            client_id = cursor.lastrowid
            log_action(session['user'], f"Додано клієнта: {name} (ID: {client_id})", 
                      table_name='clients', record_id=client_id, ip_address=request.remote_addr)
            create_notification(session['user'], f"Клієнта {name} успішно додано!", "success")
            
            flash(f"✅ Клієнта {name} успішно додано!", "success")
            return redirect(f"/client/{client_id}")
        except Exception as e:
            flash("❌ Помилка при додаванні клієнта", "error")
            print(f"Error: {e}")

    return render_template("add_clients.html")

@app.route("/edit-client/<int:client_id>", methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    db = get_db()

    if request.method == "POST":
        name = sanitize_input(request.form.get("name"))
        phone = sanitize_input(request.form.get("phone"))
        client_type = sanitize_input(request.form.get("type"))
        
        # Валідація
        errors = []
        if not validate_name(name):
            errors.append("ПІБ має містити мінімум 2 символи і лише літери")
        
        if not validate_phone(phone):
            errors.append("Невірний формат телефону")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(f"/edit-client/{client_id}")
        
        # Перевірка дублікату телефону (окрім поточного клієнта)
        existing = db.execute(
            "SELECT id FROM clients WHERE phone = ? AND id != ?", 
            (phone, client_id)
        ).fetchone()
        
        if existing:
            flash(f"❌ Телефон {phone} вже використовується іншим клієнтом", "error")
            return redirect(f"/edit-client/{client_id}")
        
        try:
            db.execute(
                "UPDATE clients SET name=?, phone=?, type=? WHERE id=?",
                (name, phone, client_type, client_id)
            )
            db.commit()
            
            log_action(session['user'], f"Оновлено клієнта: {name} (ID: {client_id})", 
                      table_name='clients', record_id=client_id, ip_address=request.remote_addr)
            
            flash("✅ Дані клієнта успішно оновлено!", "success")
            return redirect(f"/client/{client_id}")
        except Exception as e:
            flash("❌ Помилка при оновленні даних", "error")
            print(f"Error: {e}")

    client = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    
    if not client:
        flash("❌ Клієнта не знайдено", "error")
        return redirect("/clients")

    return render_template("edit_client.html", client=client)

@app.route("/delete-client/<int:client_id>")
@login_required
def delete_client(client_id):
    db = get_db()
    
    client = db.execute("SELECT name FROM clients WHERE id=?", (client_id,)).fetchone()
    
    if not client:
        flash("❌ Клієнта не знайдено", "error")
        return redirect("/clients")
    
    try:
        db.execute("DELETE FROM clients WHERE id=?", (client_id,))
        db.commit()
        
        log_action(session['user'], f"Видалено клієнта: {client['name']} (ID: {client_id})", 
                  table_name='clients', record_id=client_id, ip_address=request.remote_addr)
        
        flash(f"✅ Клієнта {client['name']} та всі пов'язані дані видалено", "success")
    except Exception as e:
        flash("❌ Помилка при видаленні клієнта", "error")
        print(f"Error: {e}")
    
    return redirect("/clients")

# ========== PROFILE ==========
@app.route("/client/<int:client_id>")
@login_required
def client_profile(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    
    if not client:
        flash("❌ Клієнта не знайдено", "error")
        return redirect("/clients")
    
    cards = db.execute(
        "SELECT * FROM cards WHERE client_id=? ORDER BY created_at DESC",
        (client_id,)
    ).fetchall()
    
    # Отримання транзакцій для графіка
    transactions = db.execute("""
        SELECT t.*, c.currency 
        FROM transactions t
        JOIN cards c ON t.card_id = c.id
        WHERE c.client_id = ?
        ORDER BY t.created_at DESC
        LIMIT 50
    """, (client_id,)).fetchall()

    rating = (
        {"label": "TRUSTED", "class": "rating-green", "score": 95}
        if client["type"] == "Юридична особа"
        else {"label": "STANDARD", "class": "rating-yellow", "score": 75}
    )

    return render_template(
        "client_profile.html",
        client=client,
        cards=cards,
        rating=rating,
        transactions=transactions
    )

@app.route("/issue-card/<int:client_id>/<currency>")
@login_required
def issue_card(client_id, currency):
    if currency not in ['UAH', 'USD', 'EUR']:
        flash("❌ Невірна валюта", "error")
        return redirect(f"/client/{client_id}")
    
    db = get_db()

    count = db.execute(
        "SELECT COUNT(*) FROM cards WHERE client_id=?",
        (client_id,)
    ).fetchone()[0]

    if count >= 3:
        flash("❌ Досягнуто ліміт карток (максимум 3)", "warning")
        return redirect(f"/client/{client_id}")

    exists = db.execute(
        "SELECT 1 FROM cards WHERE client_id=? AND currency=?",
        (client_id, currency)
    ).fetchone()

    if exists:
        flash(f"❌ У клієнта вже є картка в {currency}", "warning")
        return redirect(f"/client/{client_id}")

    # Генерація номера картки
    number = f"4441 {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
    balance = 1000.0 if currency == "UAH" else 100.0 if currency == "USD" else 50.0

    try:
        cursor = db.execute(
            "INSERT INTO cards (client_id, card_number, balance, currency) VALUES (?, ?, ?, ?)",
            (client_id, number, balance, currency)
        )
        card_id = cursor.lastrowid
        
        # Логування початкового балансу
        db.execute(
            "INSERT INTO transactions (card_id, amount, type, description) VALUES (?, ?, 'Поповнення', 'Початковий баланс')",
            (card_id, balance)
        )
        db.commit()
        
        log_action(session['user'], f"Емітовано картку {currency} (ID: {card_id})", 
                  table_name='cards', record_id=card_id, ip_address=request.remote_addr)
        
        flash(f"✅ Картку {currency} успішно створено! Номер: {number}", "success")
    except Exception as e:
        flash("❌ Помилка при створенні картки", "error")
        print(f"Error: {e}")

    return redirect(f"/client/{client_id}")

@app.route("/toggle-card/<int:card_id>")
@login_required
def toggle_card(card_id):
    db = get_db()
    card = db.execute("SELECT * FROM cards WHERE id=?", (card_id,)).fetchone()

    if card:
        new_status = "Заблокована" if card["status"] == "Активна" else "Активна"
        db.execute("UPDATE cards SET status=? WHERE id=?", (new_status, card_id))
        db.commit()
        
        status_msg = "заблоковано" if new_status == "Заблокована" else "розблоковано"
        log_action(session['user'], f"Картку {card['card_number']} {status_msg}", 
                  table_name='cards', record_id=card_id, ip_address=request.remote_addr)
        
        flash(f"✅ Картку успішно {status_msg}", "success")

    return redirect(f"/client/{card['client_id']}")

# ========== REQUESTS ==========
@app.route("/requests")
@login_required
def requests_page():
    status_filter = request.args.get('status', '')
    
    db = get_db()
    
    if status_filter and status_filter in ['Нова', 'В обробці', 'Закрита']:
        reqs = db.execute("""
            SELECT requests.*, clients.name AS client_name
            FROM requests
            JOIN clients ON requests.client_id = clients.id
            WHERE requests.status = ?
            ORDER BY requests.created_at DESC
        """, (status_filter,)).fetchall()
    else:
        reqs = db.execute("""
            SELECT requests.*, clients.name AS client_name
            FROM requests
            JOIN clients ON requests.client_id = clients.id
            ORDER BY requests.created_at DESC
        """).fetchall()
    
    # Статистика заявок
    stats = {
        "total": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
        "new": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],
        "processing": db.execute("SELECT COUNT(*) FROM requests WHERE status='В обробці'").fetchone()[0],
        "closed": db.execute("SELECT COUNT(*) FROM requests WHERE status='Закрита'").fetchone()[0]
    }
    
    return render_template("requests.html", requests=reqs, status_filter=status_filter, stats=stats)

@app.route("/add-request", methods=["GET", "POST"])
@login_required
def add_request():
    db = get_db()

    if request.method == "POST":
        client_id = request.form.get("client_id")
        service = sanitize_input(request.form.get("service"))
        
        if not validate_name(service):
            flash("❌ Назва послуги має містити лише літери", "error")
            return redirect("/add-request")
        
        try:
            cursor = db.execute(
                "INSERT INTO requests (client_id, service, status) VALUES (?, ?, 'Нова')",
                (client_id, service)
            )
            db.commit()
            
            request_id = cursor.lastrowid
            log_action(session['user'], f"Створено заявку: {service} (ID: {request_id})", 
                      table_name='requests', record_id=request_id, ip_address=request.remote_addr)
            
            flash("✅ Заявку успішно створено!", "success")
            return redirect("/requests")
        except Exception as e:
            flash("❌ Помилка при створенні заявки", "error")
            print(f"Error: {e}")

    clients = db.execute("SELECT * FROM clients ORDER BY name").fetchall()
    return render_template("add_request.html", clients=clients)

@app.route("/request/<int:req_id>/status")
@login_required
def next_status(req_id):
    db = get_db()
    req = db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()

    if req:
        status_flow = {
            "Нова": "В обробці",
            "В обробці": "Закрита"
        }
        new_status = status_flow.get(req["status"], req["status"])
        
        db.execute("UPDATE requests SET status=? WHERE id=?", (new_status, req_id))
        db.commit()
        
        log_action(session['user'], f"Змінено статус заявки {req_id}: {req['status']} → {new_status}", 
                  table_name='requests', record_id=req_id, ip_address=request.remote_addr)
        
        flash(f"✅ Статус заявки змінено на '{new_status}'", "success")

    return redirect("/requests")

@app.route("/about")
@login_required
def about_page():
    return render_template("about.html")

# ========== API & EXPORT ==========
@app.route("/api/stats")
@login_required
def api_stats():
    """API для отримання статистики"""
    db = get_db()
    stats = {
        "total_clients": db.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
        "total_cards": db.execute("SELECT COUNT(*) FROM cards").fetchone()[0],
        "active_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Активна'").fetchone()[0],
        "total_requests": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
        "new_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],
        "total_balance_uah": db.execute("SELECT SUM(balance) FROM cards WHERE currency='UAH'").fetchone()[0] or 0,
        "total_balance_usd": db.execute("SELECT SUM(balance) FROM cards WHERE currency='USD'").fetchone()[0] or 0,
        "total_balance_eur": db.execute("SELECT SUM(balance) FROM cards WHERE currency='EUR'").fetchone()[0] or 0
    }
    return jsonify(stats)

@app.route("/export/clients")
@login_required
def export_clients():
    """Експорт клієнтів у CSV"""
    db = get_db()
    clients = db.execute("SELECT * FROM clients ORDER BY id").fetchall()
    
    # Створення CSV
    output = "ID,ПІБ,Телефон,Тип,Дата реєстрації\n"
    for c in clients:
        output += f"{c['id']},{c['name']},{c['phone']},{c['type']},{c['created_at']}\n"
    
    response = make_response(output)
    response.headers["Content-Disposition"] = f"attachment; filename=clients_{datetime.now().strftime('%Y%m%d')}.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    
    log_action(session['user'], "Експортовано список клієнтів", ip_address=request.remote_addr)
    
    return response

@app.route("/card/<int:card_id>/qr")
@login_required
def generate_card_qr(card_id):
    """Генерація QR-коду для картки"""
    db = get_db()
    card = db.execute("SELECT card_number, currency FROM cards WHERE id=?", (card_id,)).fetchone()
    
    if not card:
        return jsonify({"error": "Card not found"}), 404
    
    # Створення QR-коду
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(f"CRYSTALBANK:{card['currency']}:{card['card_number']}")
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="#38bdf8", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return jsonify({"qr": f"data:image/png;base64,{qr_base64}"})

@app.route("/backup")
@login_required
def create_backup():
    """Створення резервної копії БД (тільки для адмінів)"""
    if session.get('role') != 'admin':
        flash("❌ Доступ заборонено. Тільки для адміністраторів.", "error")
        return redirect("/clients")
    
    try:
        backup_path = backup_database()
        log_action(session['user'], f"Створено резервну копію: {backup_path}", ip_address=request.remote_addr)
        flash(f"✅ Резервна копія створена: {backup_path}", "success")
    except Exception as e:
        flash(f"❌ Помилка створення резервної копії: {str(e)}", "error")
    
    return redirect("/clients")

# ========== NOTIFICATIONS ==========
@app.route("/notifications")
@login_required
def get_notifications():
    """Отримання нотифікацій користувача"""
    db = get_db()
    notifications = db.execute(
        "SELECT * FROM notifications WHERE user=? ORDER BY created_at DESC LIMIT 10",
        (session['user'],)
    ).fetchall()
    
    return jsonify([dict(n) for n in notifications])

@app.route("/notifications/mark-read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    """Позначити нотифікацію як прочитану"""
    db = get_db()
    db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user=?", 
              (notif_id, session['user']))
    db.commit()
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
