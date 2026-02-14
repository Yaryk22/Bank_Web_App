# ========== ІМПОРТИ БІБЛІОТЕК ==========
# random - для генерації випадкових чисел (номери карток)
# secrets - для генерації криптографічно безпечних секретних ключів
import random
import secrets

# Flask - основний фреймворк для веб-додатку
from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_file, make_response

# Werkzeug - інструменти для безпеки паролів (хешування, перевірка)
from werkzeug.security import check_password_hash, generate_password_hash

# Імпорт функцій роботи з базою даних з файлу db.py
from db import init_db, get_db, log_action, backup_database

# functools.wraps - для створення декораторів (обгортки функцій)
from functools import wraps

# datetime - робота з датою і часом
from datetime import timedelta, datetime

# re - регулярні вирази для валідації даних
import re

# BytesIO - робота з бінарними даними в пам'яті
from io import BytesIO

# qrcode - генерація QR-кодів
import qrcode

# base64 - кодування даних в base64 формат
import base64

# Створення екземпляру Flask додатку
app = Flask(__name__)

# ========== НАЛАШТУВАННЯ БЕЗПЕКИ ==========
# Секретний ключ для шифрування сесій (випадковий 32-байтний hex)
app.secret_key = secrets.token_hex(32)

# Сесія зберігається постійно (не видаляється при закритті браузера)
app.config['SESSION_PERMANENT'] = True

# Час життя сесії - 30 хвилин
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# SESSION_COOKIE_SECURE = True - cookie тільки через HTTPS (для продакшену)
app.config['SESSION_COOKIE_SECURE'] = False  # False для розробки без HTTPS

# HttpOnly - cookie недоступні через JavaScript (захист від XSS атак)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# SameSite - захист від CSRF атак
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Максимальний розмір файлів для завантаження - 16 МБ
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# ========== ФУНКЦІЯ ДОДАВАННЯ ЗАГОЛОВКІВ БЕЗПЕКИ ==========
@app.after_request
def set_security_headers(response):
    """
    Додає заголовки безпеки до кожної відповіді сервера
    Викликається автоматично після кожного запиту
    """
    # X-Content-Type-Options - браузер не намагається визначити тип файлу самостійно
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # X-Frame-Options - захист від clickjacking (заборона відображення в iframe)
    response.headers['X-Frame-Options'] = 'DENY'
    
    # X-XSS-Protection - увімкнення захисту від XSS атак у старих браузерах
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # HSTS - примусове використання HTTPS протягом року
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # CSP - Content Security Policy (які ресурси можна завантажувати)
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com https://bank.gov.ua; img-src 'self' data:;"
    
    return response

# ========== ОБМЕЖЕННЯ СПРОБ ВХОДУ (Rate Limiting) ==========
# Словник для зберігання спроб входу по IP адресах
login_attempts = {}

# Максимальна кількість невдалих спроб входу
MAX_LOGIN_ATTEMPTS = 5

# Час блокування після перевищення ліміту (300 секунд = 5 хвилин)
LOCKOUT_TIME = 300

# ========== ІНІЦІАЛІЗАЦІЯ БАЗИ ДАНИХ ==========
# Викликаємо функцію ініціалізації БД
init_db()

# Контекст додатку - для роботи з БД при запуску
with app.app_context():
    # Отримуємо підключення до БД
    db = get_db()
    
    # ========== СТВОРЕННЯ ТАБЛИЦІ ТРАНЗАКЦІЙ ==========
    db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Унікальний ідентифікатор
            card_id INTEGER NOT NULL,              -- ID картки (зовнішній ключ)
            amount REAL NOT NULL,                  -- Сума операції
            type TEXT NOT NULL CHECK(type IN ('Поповнення', 'Зняття', 'Переказ')),  -- Тип операції
            description TEXT,                      -- Опис транзакції
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата створення
            FOREIGN KEY (card_id) REFERENCES cards (id) ON DELETE CASCADE  -- Видалення каскадом
        )
    """)
    
    # ========== СТВОРЕННЯ ТАБЛИЦІ НОТИФІКАЦІЙ ==========
    db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Унікальний ID
            user TEXT NOT NULL,                    -- Логін користувача
            message TEXT NOT NULL,                 -- Текст повідомлення
            type TEXT DEFAULT 'info' CHECK(type IN ('success', 'error', 'warning', 'info')),  -- Тип повідомлення
            is_read BOOLEAN DEFAULT 0,             -- Прочитано (0 - ні, 1 - так)
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Дата створення
        )
    """)
    
    # Зберігаємо зміни в БД
    db.commit()
    print("✅ Кристал Банк: Система готова до роботи")

# ========== ДОПОМІЖНІ ФУНКЦІЇ ==========

def sanitize_input(text):
    """
    Очищення введених користувачем даних від небезпечних символів
    Захист від XSS атак (видаляємо <, >, ", ')
    """
    if not text:
        return ""
    # Видаляємо небезпечні символи за допомогою регулярного виразу
    return re.sub(r'[<>"\']', '', str(text).strip())

def validate_phone(phone):
    """
    Перевірка правильності формату телефонного номера
    Формат: +XXXXXXXXXXX (7-15 цифр після +, але не починається з +7)
    """
    pattern = r'^\+(?!7)[0-9]{7,15}$'
    return re.match(pattern, phone) is not None

def validate_name(name):
    """
    Перевірка правильності формату імені
    Дозволені: літери (латиниця/кирилиця), пробіли, апострофи, тире, крапки
    Мінімум 2 символи
    """
    pattern = r'^[a-zA-Zа-яА-ЯіІїЇєЄґҐ\s\'\-\.]+$'
    return re.match(pattern, name) is not None and len(name) >= 2

def check_rate_limit(ip):
    """
    Перевірка чи не заблоковано IP через забагато невдалих спроб входу
    Повертає False якщо IP заблоковано
    """
    if ip in login_attempts:
        # Отримуємо кількість спроб і час останньої спроби
        attempts, last_attempt = login_attempts[ip]
        
        # Перевіряємо чи пройшов час блокування
        if datetime.now().timestamp() - last_attempt < LOCKOUT_TIME:
            # Якщо спроб більше ліміту - блокуємо
            if attempts >= MAX_LOGIN_ATTEMPTS:
                return False
    return True

def record_login_attempt(ip, success=False):
    """
    Запис спроби входу в систему
    Якщо вхід успішний - очищаємо лічильник
    Якщо невдалий - збільшуємо кількість спроб
    """
    if ip not in login_attempts:
        # Ініціалізуємо: [кількість спроб, час]
        login_attempts[ip] = [0, datetime.now().timestamp()]
    
    if success:
        # Успішний вхід - видаляємо запис
        login_attempts.pop(ip, None)
    else:
        # Невдалий вхід - збільшуємо лічильник
        attempts, _ = login_attempts[ip]
        login_attempts[ip] = [attempts + 1, datetime.now().timestamp()]

def create_notification(user, message, notification_type='info'):
    """
    Створення нотифікації (повідомлення) для користувача
    Зберігається в БД для подальшого відображення
    """
    db = get_db()
    db.execute(
        "INSERT INTO notifications (user, message, type) VALUES (?, ?, ?)",
        (user, message, notification_type)
    )
    db.commit()

# ========== ДЕКОРАТОР ДЛЯ ЗАХИСТУ МАРШРУТІВ ==========
def login_required(f):
    """
    Декоратор для перевірки авторизації користувача
    Використовується для захисту маршрутів, які потребують входу
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Перевіряємо чи є користувач в сесії
        if "user" not in session:
            flash("Будь ласка, увійдіть в систему", "error")
            return redirect("/login")
        # Якщо авторизований - викликаємо оригінальну функцію
        return f(*args, **kwargs)
    return decorated

# ========== ОБРОБНИКИ ПОМИЛОК ==========

@app.errorhandler(404)
def not_found(e):
    """
    Обробник помилки 404 - сторінка не знайдена
    """
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    """
    Обробник помилки 500 - внутрішня помилка сервера
    Логує помилку для аналізу
    """
    log_action(session.get('user', 'anonymous'), f'500 Error: {str(e)}', ip_address=request.remote_addr)
    return render_template('500.html'), 500

# ========== АУТЕНТИФІКАЦІЯ (ВХІД/ВИХІД) ==========

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Сторінка входу в систему
    GET - відображення форми входу
    POST - обробка спроби входу
    """
    if request.method == "POST":
        # Отримуємо IP адресу користувача
        ip = request.remote_addr
        
        # Перевіряємо чи не заблоковано IP
        if not check_rate_limit(ip):
            remaining_time = int(LOCKOUT_TIME / 60)
            flash(f"⚠️ Забагато невдалих спроб. Спробуйте через {remaining_time} хвилин", "error")
            return render_template("login.html")
        
        # Отримуємо та очищаємо дані з форми
        username = sanitize_input(request.form.get("username"))
        password = request.form.get("password")

        # Перевірка чи заповнені всі поля
        if not username or not password:
            flash("Заповніть всі поля", "error")
            return render_template("login.html")

        # Шукаємо користувача в БД
        db = get_db()
        user = db.execute(
            "SELECT * FROM employees WHERE username = ? AND is_active = 1",
            (username,)
        ).fetchone()

        # Перевірка логіну та пароля
        if user and check_password_hash(user["password"], password):
            # УСПІШНИЙ ВХІД
            # Очищаємо стару сесію
            session.clear()
            
            # Зберігаємо дані в сесію
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["login_time"] = datetime.now().isoformat()
            
            # Оновлюємо час останнього входу в БД
            db.execute(
                "UPDATE employees SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user["id"],)
            )
            db.commit()
            
            # Записуємо успішний вхід
            record_login_attempt(ip, success=True)
            log_action(username, "Успішний вхід в систему", ip_address=ip)
            create_notification(username, "Ви увійшли в систему", "success")
            
            flash(f"Вітаємо, {username}!", "success")
            return redirect("/clients")

        # НЕВДАЛИЙ ВХІД
        record_login_attempt(ip, success=False)
        log_action(username or "невідомий", "Невдала спроба входу", ip_address=ip)
        flash("Невірний логін або пароль", "error")

    # GET запит - показуємо форму входу
    return render_template("login.html")

@app.route("/logout")
def logout():
    """
    Вихід з системи
    Очищає сесію та перенаправляє на сторінку входу
    """
    user = session.get("user")
    if user:
        # Логуємо вихід
        log_action(user, "Вихід з системи", ip_address=request.remote_addr)
    
    # Очищаємо всі дані сесії
    session.clear()
    flash("Ви успішно вийшли з системи", "info")
    return redirect("/login")

@app.route("/")
def index():
    """
    Головна сторінка
    Перенаправляє на /clients якщо авторизований, інакше на /login
    """
    if "user" in session:
        return redirect("/clients")
    return redirect("/login")

# ========== РОБОТА З КЛІЄНТАМИ ==========

@app.route("/clients")
@login_required
def clients_page():
    """
    Сторінка зі списком клієнтів
    Підтримує пошук та фільтрацію за типом
    """
    # Отримуємо параметри пошуку з URL
    search_query = sanitize_input(request.args.get('search', ''))
    client_type = request.args.get('type', '')
    
    db = get_db()
    
    # Формуємо SQL запит з фільтрами
    if search_query or client_type:
        query = "SELECT * FROM clients WHERE 1=1"
        params = []
        
        # Додаємо умову пошуку по імені або телефону
        if search_query:
            query += " AND (name LIKE ? OR phone LIKE ?)"
            params.extend([f"%{search_query}%", f"%{search_query}%"])
        
        # Додаємо умову фільтрації за типом клієнта
        if client_type and client_type in ['Фізична особа', 'Юридична особа']:
            query += " AND type = ?"
            params.append(client_type)
        
        query += " ORDER BY id DESC"
        clients = db.execute(query, params).fetchall()
    else:
        # Без фільтрів - всі клієнти
        clients = db.execute("SELECT * FROM clients ORDER BY id DESC").fetchall()

    # Збираємо статистику для дашборду
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
    """
    Додавання нового клієнта
    GET - форма додавання
    POST - обробка додавання
    """
    if request.method == "POST":
        # Отримуємо та очищаємо дані з форми
        name = sanitize_input(request.form.get("name"))
        phone = sanitize_input(request.form.get("phone"))
        client_type = sanitize_input(request.form.get("type"))
        
        # ВАЛІДАЦІЯ ДАНИХ
        errors = []
        
        # Перевірка імені
        if not validate_name(name):
            errors.append("ПІБ має містити мінімум 2 символи і лише літери")
        
        # Перевірка телефону
        if not validate_phone(phone):
            errors.append("Невірний формат телефону. Формат: +380XXXXXXXXX")
        
        # Перевірка типу клієнта
        if client_type not in ["Фізична особа", "Юридична особа"]:
            errors.append("Невірний тип клієнта")
        
        # Якщо є помилки - показуємо їх
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("add_clients.html")
        
        db = get_db()
        
        # Перевірка чи не існує вже клієнт з таким телефоном
        existing = db.execute("SELECT id FROM clients WHERE phone = ?", (phone,)).fetchone()
        if existing:
            flash(f"❌ Клієнт з телефоном {phone} вже існує в системі", "error")
            return render_template("add_clients.html")
        
        try:
            # Вставка нового клієнта в БД
            cursor = db.execute(
                "INSERT INTO clients (name, phone, type) VALUES (?, ?, ?)",
                (name, phone, client_type)
            )
            db.commit()
            
            # Отримуємо ID щойно створеного клієнта
            client_id = cursor.lastrowid
            
            # Логування дії
            log_action(session['user'], f"Додано клієнта: {name} (ID: {client_id})", 
                      table_name='clients', record_id=client_id, ip_address=request.remote_addr)
            
            # Створюємо нотифікацію
            create_notification(session['user'], f"Клієнта {name} успішно додано!", "success")
            
            flash(f"✅ Клієнта {name} успішно додано!", "success")
            return redirect(f"/client/{client_id}")
        except Exception as e:
            flash("❌ Помилка при додаванні клієнта", "error")
            print(f"Error: {e}")

    # GET запит - показуємо форму
    return render_template("add_clients.html")

@app.route("/edit-client/<int:client_id>", methods=["GET", "POST"])
@login_required
def edit_client(client_id):
    """
    Редагування даних клієнта
    GET - форма редагування
    POST - збереження змін
    """
    db = get_db()

    if request.method == "POST":
        # Отримуємо дані з форми
        name = sanitize_input(request.form.get("name"))
        phone = sanitize_input(request.form.get("phone"))
        client_type = sanitize_input(request.form.get("type"))
        
        # ВАЛІДАЦІЯ
        errors = []
        if not validate_name(name):
            errors.append("ПІБ має містити мінімум 2 символи і лише літери")
        
        if not validate_phone(phone):
            errors.append("Невірний формат телефону")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(f"/edit-client/{client_id}")
        
        # Перевірка чи не використовує хтось інший цей телефон
        existing = db.execute(
            "SELECT id FROM clients WHERE phone = ? AND id != ?", 
            (phone, client_id)
        ).fetchone()
        
        if existing:
            flash(f"❌ Телефон {phone} вже використовується іншим клієнтом", "error")
            return redirect(f"/edit-client/{client_id}")
        
        try:
            # Оновлення даних клієнта
            db.execute(
                "UPDATE clients SET name=?, phone=?, type=? WHERE id=?",
                (name, phone, client_type, client_id)
            )
            db.commit()
            
            # Логування
            log_action(session['user'], f"Оновлено клієнта: {name} (ID: {client_id})", 
                      table_name='clients', record_id=client_id, ip_address=request.remote_addr)
            
            flash("✅ Дані клієнта успішно оновлено!", "success")
            return redirect(f"/client/{client_id}")
        except Exception as e:
            flash("❌ Помилка при оновленні даних", "error")
            print(f"Error: {e}")

    # GET - завантажуємо дані клієнта для форми
    client = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    
    if not client:
        flash("❌ Клієнта не знайдено", "error")
        return redirect("/clients")

    return render_template("edit_client.html", client=client)

@app.route("/delete-client/<int:client_id>")
@login_required
def delete_client(client_id):
    """
    Видалення клієнта
    Також видаляються всі пов'язані дані (каскадне видалення)
    """
    db = get_db()
    
    # Спочатку отримуємо ім'я для логування
    client = db.execute("SELECT name FROM clients WHERE id=?", (client_id,)).fetchone()
    
    if not client:
        flash("❌ Клієнта не знайдено", "error")
        return redirect("/clients")
    
    try:
        # Видалення клієнта (каскадно видалить картки, заявки тощо)
        db.execute("DELETE FROM clients WHERE id=?", (client_id,))
        db.commit()
        
        # Логування видалення
        log_action(session['user'], f"Видалено клієнта: {client['name']} (ID: {client_id})", 
                  table_name='clients', record_id=client_id, ip_address=request.remote_addr)
        
        flash(f"✅ Клієнта {client['name']} та всі пов'язані дані видалено", "success")
    except Exception as e:
        flash("❌ Помилка при видаленні клієнта", "error")
        print(f"Error: {e}")
    
    return redirect("/clients")

# ========== ПРОФІЛЬ КЛІЄНТА ==========

@app.route("/client/<int:client_id>")
@login_required
def client_profile(client_id):
    """
    Детальна інформація про клієнта
    Показує картки, транзакції, рейтинг
    """
    db = get_db()
    
    # Отримуємо дані клієнта
    client = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    
    if not client:
        flash("❌ Клієнта не знайдено", "error")
        return redirect("/clients")
    
    # Отримуємо всі картки клієнта
    cards = db.execute(
        "SELECT * FROM cards WHERE client_id=? ORDER BY created_at DESC",
        (client_id,)
    ).fetchall()
    
    # Отримуємо останні 50 транзакцій для графіка активності
    transactions = db.execute("""
        SELECT t.*, c.currency 
        FROM transactions t
        JOIN cards c ON t.card_id = c.id
        WHERE c.client_id = ?
        ORDER BY t.created_at DESC
        LIMIT 50
    """, (client_id,)).fetchall()

    # Обчислення рейтингу клієнта (залежить від типу)
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
    """
    Видача нової картки клієнту
    Перевіряє ліміти та наявність карток у валюті
    """
    # Перевірка валюти
    if currency not in ['UAH', 'USD', 'EUR']:
        flash("❌ Невірна валюта", "error")
        return redirect(f"/client/{client_id}")
    
    db = get_db()

    # Перевірка ліміту карток (максимум 3)
    count = db.execute(
        "SELECT COUNT(*) FROM cards WHERE client_id=?",
        (client_id,)
    ).fetchone()[0]

    if count >= 3:
        flash("❌ Досягнуто ліміт карток (максимум 3)", "warning")
        return redirect(f"/client/{client_id}")

    # Перевірка чи немає вже картки в цій валюті
    exists = db.execute(
        "SELECT 1 FROM cards WHERE client_id=? AND currency=?",
        (client_id, currency)
    ).fetchone()

    if exists:
        flash(f"❌ У клієнта вже є картка в {currency}", "warning")
        return redirect(f"/client/{client_id}")

    # Генерація номера картки (формат: 4441 XXXX XXXX XXXX)
    number = f"4441 {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
    
    # Початковий баланс залежить від валюти
    balance = 1000.0 if currency == "UAH" else 100.0 if currency == "USD" else 50.0

    try:
        # Створення нової картки
        cursor = db.execute(
            "INSERT INTO cards (client_id, card_number, balance, currency) VALUES (?, ?, ?, ?)",
            (client_id, number, balance, currency)
        )
        card_id = cursor.lastrowid
        
        # Логування початкового поповнення
        db.execute(
            "INSERT INTO transactions (card_id, amount, type, description) VALUES (?, ?, 'Поповнення', 'Початковий баланс')",
            (card_id, balance)
        )
        db.commit()
        
        # Логування видачі картки
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
    """
    Блокування/розблокування картки
    Перемикає статус між 'Активна' та 'Заблокована'
    """
    db = get_db()
    card = db.execute("SELECT * FROM cards WHERE id=?", (card_id,)).fetchone()

    if card:
        # Визначаємо новий статус (протилежний поточному)
        new_status = "Заблокована" if card["status"] == "Активна" else "Активна"
        
        # Оновлюємо статус
        db.execute("UPDATE cards SET status=? WHERE id=?", (new_status, card_id))
        db.commit()
        
        # Формуємо текст для логування
        status_msg = "заблоковано" if new_status == "Заблокована" else "розблоковано"
        log_action(session['user'], f"Картку {card['card_number']} {status_msg}", 
                  table_name='cards', record_id=card_id, ip_address=request.remote_addr)
        
        flash(f"✅ Картку успішно {status_msg}", "success")

    return redirect(f"/client/{card['client_id']}")

# ========== ЗАЯВКИ ==========

@app.route("/requests")
@login_required
def requests_page():
    """
    Сторінка зі списком заявок
    Підтримує фільтрацію за статусом
    """
    # Отримуємо фільтр статусу з URL
    status_filter = request.args.get('status', '')
    
    db = get_db()
    
    # Формуємо запит з фільтром або без
    if status_filter and status_filter in ['Нова', 'В обробці', 'Закрита']:
        reqs = db.execute("""
            SELECT requests.*, clients.name AS client_name
            FROM requests
            JOIN clients ON requests.client_id = clients.id
            WHERE requests.status = ?
            ORDER BY requests.created_at DESC
        """, (status_filter,)).fetchall()
    else:
        # Без фільтра - всі заявки з іменами клієнтів
        reqs = db.execute("""
            SELECT requests.*, clients.name AS client_name
            FROM requests
            JOIN clients ON requests.client_id = clients.id
            ORDER BY requests.created_at DESC
        """).fetchall()
    
    # Статистика по заявках
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
    """
    Створення нової заявки на послугу
    """
    db = get_db()

    if request.method == "POST":
        client_id = request.form.get("client_id")
        service = sanitize_input(request.form.get("service"))
        
        # Валідація назви послуги
        if not validate_name(service):
            flash("❌ Назва послуги має містити лише літери", "error")
            return redirect("/add-request")
        
        try:
            # Створення заявки зі статусом "Нова"
            cursor = db.execute(
                "INSERT INTO requests (client_id, service, status) VALUES (?, ?, 'Нова')",
                (client_id, service)
            )
            db.commit()
            
            request_id = cursor.lastrowid
            
            # Логування
            log_action(session['user'], f"Створено заявку: {service} (ID: {request_id})", 
                      table_name='requests', record_id=request_id, ip_address=request.remote_addr)
            
            flash("✅ Заявку успішно створено!", "success")
            return redirect("/requests")
        except Exception as e:
            flash("❌ Помилка при створенні заявки", "error")
            print(f"Error: {e}")

    # GET - завантажуємо список клієнтів для dropdown
    clients = db.execute("SELECT * FROM clients ORDER BY name").fetchall()
    return render_template("add_request.html", clients=clients)

@app.route("/request/<int:req_id>/status")
@login_required
def next_status(req_id):
    """
    Зміна статусу заявки на наступний
    Нова → В обробці → Закрита
    """
    db = get_db()
    req = db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()

    if req:
        # Словник переходів статусів
        status_flow = {
            "Нова": "В обробці",
            "В обробці": "Закрита"
        }
        
        # Визначаємо новий статус
        new_status = status_flow.get(req["status"], req["status"])
        
        # Оновлюємо статус
        db.execute("UPDATE requests SET status=? WHERE id=?", (new_status, req_id))
        db.commit()
        
        # Логування зміни статусу
        log_action(session['user'], f"Змінено статус заявки {req_id}: {req['status']} → {new_status}", 
                  table_name='requests', record_id=req_id, ip_address=request.remote_addr)
        
        flash(f"✅ Статус заявки змінено на '{new_status}'", "success")

    return redirect("/requests")

@app.route("/about")
@login_required
def about_page():
    """
    Сторінка "Про систему"
    """
    return render_template("about.html")

# ========== API ТА ЕКСПОРТ ДАНИХ ==========

@app.route("/api/stats")
@login_required
def api_stats():
    """
    API ендпоінт для отримання статистики в JSON форматі
    Використовується для дашбордів та графіків
    """
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
    """
    Експорт списку клієнтів у CSV файл
    Для завантаження та аналізу в Excel
    """
    db = get_db()
    clients = db.execute("SELECT * FROM clients ORDER BY id").fetchall()
    
    # Формування CSV (заголовок + дані)
    output = "ID,ПІБ,Телефон,Тип,Дата реєстрації\n"
    for c in clients:
        output += f"{c['id']},{c['name']},{c['phone']},{c['type']},{c['created_at']}\n"
    
    # Створення відповіді з файлом
    response = make_response(output)
    response.headers["Content-Disposition"] = f"attachment; filename=clients_{datetime.now().strftime('%Y%m%d')}.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    
    # Логування експорту
    log_action(session['user'], "Експортовано список клієнтів", ip_address=request.remote_addr)
    
    return response

@app.route("/card/<int:card_id>/qr")
@login_required
def generate_card_qr(card_id):
    """
    Генерація QR-коду для картки
    Повертає base64 зображення QR-коду
    """
    db = get_db()
    card = db.execute("SELECT card_number, currency FROM cards WHERE id=?", (card_id,)).fetchone()
    
    if not card:
        return jsonify({"error": "Card not found"}), 404
    
    # Створення QR-коду з даними картки
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(f"CRYSTALBANK:{card['currency']}:{card['card_number']}")
    qr.make(fit=True)
    
    # Генерація зображення (блакитний колір)
    img = qr.make_image(fill_color="#38bdf8", back_color="white")
    
    # Конвертація в base64 для передачі через JSON
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return jsonify({"qr": f"data:image/png;base64,{qr_base64}"})

@app.route("/backup")
@login_required
def create_backup():
    """
    Створення резервної копії бази даних
    Доступно тільки адміністраторам
    """
    # Перевірка ролі користувача
    if session.get('role') != 'admin':
        flash("❌ Доступ заборонено. Тільки для адміністраторів.", "error")
        return redirect("/clients")
    
    try:
        # Виклик функції бекапу з db.py
        backup_path = backup_database()
        log_action(session['user'], f"Створено резервну копію: {backup_path}", ip_address=request.remote_addr)
        flash(f"✅ Резервна копія створена: {backup_path}", "success")
    except Exception as e:
        flash(f"❌ Помилка створення резервної копії: {str(e)}", "error")
    
    return redirect("/clients")

# ========== НОТИФІКАЦІЇ ==========

@app.route("/notifications")
@login_required
def get_notifications():
    """
    API для отримання нотифікацій поточного користувача
    Повертає останні 10 повідомлень у JSON
    """
    db = get_db()
    notifications = db.execute(
        "SELECT * FROM notifications WHERE user=? ORDER BY created_at DESC LIMIT 10",
        (session['user'],)
    ).fetchall()
    
    # Конвертація Row об'єктів в словники
    return jsonify([dict(n) for n in notifications])

@app.route("/notifications/mark-read/<int:notif_id>", methods=["POST"])
@login_required
def mark_notification_read(notif_id):
    """
    Позначити нотифікацію як прочитану
    POST запит для зміни статусу повідомлення
    """
    db = get_db()
    db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user=?", 
              (notif_id, session['user']))
    db.commit()
    return jsonify({"success": True})

# ========== ЗАПУСК ДОДАТКУ ==========
if __name__ == "__main__":
    # Запуск Flask сервера
    # debug=True - режим розробки з автоперезавантаженням
    # host='0.0.0.0' - доступ з будь-якої IP адреси
    # port=5000 - порт сервера
    app.run(debug=True, host='0.0.0.0', port=5000)
