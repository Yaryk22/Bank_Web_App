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

app = Flask(__name__)  # Ініціалізація Flask додатку

# ========== ПОКРАЩЕНА БЕЗПЕКА ==========
app.secret_key = secrets.token_hex(32)  # Генерація безпечного ключа сесії
app.config['SESSION_PERMANENT'] = True  # Сесія зберігається після закриття браузера
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Сесія діє 30 хвилин
app.config['SESSION_COOKIE_SECURE'] = False  # True при HTTPS, зараз False для локального тестування
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Cookie недоступна для JavaScript (захист від XSS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Захист від CSRF атак
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Максимальний розмір завантаження - 16MB

# Security Headers - додаються до кожної відповіді для захисту від атак
@app.after_request  # Виконується після кожного запиту
def set_security_headers(response):  # Функція установки заголовків безпеки
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Заборона MIME-type sniffing
    response.headers['X-Frame-Options'] = 'DENY'  # Заборона вставлення в iframe (clickjacking)
    response.headers['X-XSS-Protection'] = '1; mode=block'  # Активація XSS-фільтру браузера
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # Примус HTTPS на рік
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com https://bank.gov.ua; img-src 's[...]  # Політика контенту
    return response  # Повернення відповіді з новими заголовками

# Rate Limiting - захист від brute-force атак на вхід
login_attempts = {}  # Словник для зберігання спроб входу по IP
MAX_LOGIN_ATTEMPTS = 5  # Максимальна кількість невдалих спроб
LOCKOUT_TIME = 300  # Час блокування IP (у секундах) - 5 хвилин

# ========== ІНІЦІАЛІЗАЦІЯ БД ==========
init_db()  # Ініціалізація бази даних

with app.app_context():  # Контекст додатку для роботи з БД
    db = get_db()  # Отримання з'єднання з БД
    
    # Додаткові таблиці для розширеного функціоналу
    db.execute("""  # Таблиця транзакцій (переводи, поповнення, зняття)
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  # Унікальний ID транзакції
            card_id INTEGER NOT NULL,  # ID картки
            amount REAL NOT NULL,  # Сума операції
            type TEXT NOT NULL CHECK(type IN ('Поповнення', 'Зняття', 'Переказ')),  # Тип операції
            description TEXT,  # Опис операції
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  # Час створення
            FOREIGN KEY (card_id) REFERENCES cards (id) ON DELETE CASCADE  # Зв'язок з таблицею карток
        )
    """)
    
    db.execute("""  # Таблиця нотифікацій для користувачів
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  # Унікальний ID нотифікації
            user TEXT NOT NULL,  # Користувач, якому належить нотифікація
            message TEXT NOT NULL,  # Текст повідомлення
            type TEXT DEFAULT 'info' CHECK(type IN ('success', 'error', 'warning', 'info')),  # Тип (успіх/помилка/тощо)
            is_read BOOLEAN DEFAULT 0,  # Прочитана або ні
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  # Час створення
        )
    """)
    
    db.commit()  # Збереження змін в БД
    print("✅ Кристал Банк: Система готова до роботи")  # Повідомлення про готовність

# ========== HELPER FUNCTIONS ==========
def sanitize_input(text):  # Очищення введених даних від небезпечних символів
    """Очищення введених даних"""
    if not text:  # Якщо текст порожній
        return ""  # Повернути порожній рядок
    return re.sub(r'[<>"\']', '', str(text).strip())  # Видалити < > " ' та пробіли по краях

def validate_phone(phone):  # Перевірка формату телефону
    """Валідація номера телефону"""
    pattern = r'^\+(?!7)[0-9]{7,15}$'  # Регулярний вираз: +7XX... не дозволено, 7-15 цифр
    return re.match(pattern, phone) is not None  # True якщо формат правильний

def validate_name(name):  # Перевірка формату імені
    """Валідація імені"""
    pattern = r'^[a-zA-Zа-яА-ЯіІїЇєЄґҐ\s\'\-\.]+$'  # Дозволено латиниця, кирилиця, апострофи, дефіси
    return re.match(pattern, name) is not None and len(name) >= 2  # True якщо формат правильний і довжина >= 2

def check_rate_limit(ip):  # Перевірка чи IP заблокований після багатьох спроб входу
    """Перевірка обмеження спроб входу"""
    if ip in login_attempts:  # Якщо IP є в списку спроб
        attempts, last_attempt = login_attempts[ip]  # Отримати кількість спроб і час останньої
        if datetime.now().timestamp() - last_attempt < LOCKOUT_TIME:  # Якщо час блокування не пройшов
            if attempts >= MAX_LOGIN_ATTEMPTS:  # Якщо кількість спроб перевищена
                return False  # IP заблокований
    return True  # IP не заблокований

def record_login_attempt(ip, success=False):  # Запис спроби входу (успішної або невдалої)
    """Запис спроби входу"""
    if ip not in login_attempts:  # Якщо це перша спроба з цього IP
        login_attempts[ip] = [0, datetime.now().timestamp()]  # Ініціалізувати [спроби, час]
    
    if success:  # Якщо в��ід успішний
        login_attempts.pop(ip, None)  # Видалити IP зі списку спроб
    else:  # Якщо вхід невдалий
        attempts, _ = login_attempts[ip]  # Отримати поточну кількість спроб
        login_attempts[ip] = [attempts + 1, datetime.now().timestamp()]  # Збільшити на 1 і оновити час

def create_notification(user, message, notification_type='info'):  # Створення нотифікації в БД
    """Створення нотифікації"""
    db = get_db()  # Отримати з'єднання з БД
    db.execute(  # Вставити новий запис
        "INSERT INTO notifications (user, message, type) VALUES (?, ?, ?)",
        (user, message, notification_type)  # Параметри: користувач, текст, тип
    )
    db.commit()  # Збереження змін

# ========== DECORATOR ==========
def login_required(f):  # Декоратор для перевірки авторизації користувача
    @wraps(f)  # Зберегти оригінальне ім'я функції
    def decorated(*args, **kwargs):  # Обгортка функції
        if "user" not in session:  # Якщо користувач не в сесії (не авторизований)
            flash("Будь ласка, увійдіть в систему", "error")  # Вивести повідомлення про помилку
            return redirect("/login")  # Перенаправити на сторінку входу
        return f(*args, **kwargs)  # Інакше виконати оригінальну функцію
    return decorated  # Повернути обгортку

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)  # Обробник помилки 404 (сторінка не знайдена)
def not_found(e):  # Функція обробки помилки
    return render_template('404.html'), 404  # Вивести шаблон 404 з кодом 404

@app.errorhandler(500)  # Обробник помилки 500 (помилка сервера)
def server_error(e):  # Функція обробки помилки
    log_action(session.get('user', 'anonymous'), f'500 Error: {str(e)}', ip_address=request.remote_addr)  # Залогувати помилку
    return render_template('500.html'), 500  # Вивести шаблон помилки сервера

# ========== AUTHENTICATION ==========
@app.route("/login", methods=["GET", "POST"])  # Маршрут входу (GET - форма, POST - обробка)
def login():  # Функція для входу в систему
    if request.method == "POST":  # Якщо форма відправлена
        ip = request.remote_addr  # Отримати IP адресу клієнта
        
        if not check_rate_limit(ip):  # Перевірити чи IP не заблокований
            remaining_time = int(LOCKOUT_TIME / 60)  # Обчислити час блокування в хвилинах
            flash(f"⚠️ Забагато невдалих спроб. Спробуйте через {remaining_time} хвилин", "error")  # Вивести повідомлення
            return render_template("login.html")  # Повернути форму входу
        
        username = sanitize_input(request.form.get("username"))  # Отримати і очистити логін
        password = request.form.get("password")  # Отримати пароль

        if not username or not password:  # Якщо одне з полів порожнє
            flash("Заповніть всі поля", "error")  # Помилка
            return render_template("login.html")  # Повернути форму

        db = get_db()  # Отримати з'єднання з БД
        user = db.execute(  # Знайти користувача в БД
            "SELECT * FROM employees WHERE username = ? AND is_active = 1",
            (username,)  # Шукати активного користувача з таким логіном
        ).fetchone()  # Отримати перший результат

        if user and check_password_hash(user["password"], password):  # Якщо користувач існує і пароль правильний
            session.clear()  # Очистити стару сесію
            session["user"] = user["username"]  # Встановити логін в сесію
            session["role"] = user["role"]  # Встановити роль в сесію
            session["login_time"] = datetime.now().isoformat()  # Встановити час входу
            
            # Оновлення last_login
            db.execute(  # Оновити час останнього входу в БД
                "UPDATE employees SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user["id"],)  # Для даного користувача
            )
            db.commit()  # Збереження змін
            
            record_login_attempt(ip, success=True)  # Записати успішну спробу (очистити лічильник)
            log_action(username, "Успішний вхід в систему", ip_address=ip)  # Залогувати успішний вхід
            create_notification(username, "Ви увійшли в систему", "success")  # Створити нотифікацію
            
            flash(f"Вітаємо, {username}!", "success")  # Вивести привіт
            return redirect("/clients")  # Перенаправити на сторінку клієнтів

        record_login_attempt(ip, success=False)  # Записати невдалу спробу (збільшити лічильник)
        log_action(username or "невідомий", "Невдала спроба входу", ip_address=ip)  # Залогувати помилку
        flash("Невірний логін або пароль", "error")  # Вивести помилку

    return render_template("login.html")  # Показати форму входу при GET запиті

@app.route("/logout")  # Маршрут виходу з системи
def logout():  # Функція для виходу
    user = session.get("user")  # Отримати логін з сесії
    if user:  # Якщо користувач авторизований
        log_action(user, "Вихід з системи", ip_address=request.remote_addr)  # Залогувати вихід
    session.clear()  # Очистити сесію
    flash("Ви успішно вийшли з системи", "info")  # Вивести повідомлення
    return redirect("/login")  # Перенаправити на сторінку входу

@app.route("/")  # Головний маршрут
def index():  # Головна сторінка
    if "user" in session:  # Якщо користувач авторизований
        return redirect("/clients")  # Перенаправити на клієнтів
    return redirect("/login")  # Інакше - на вхід

# ========== CLIENTS ==========
@app.route("/clients")  # Маршрут списку клієнтів
@login_required  # Потребує авторизації
def clients_page():  # Функція сторінки клієнтів
    search_query = sanitize_input(request.args.get('search', ''))  # Отримати й очистити пошуковий запит
    client_type = request.args.get('type', '')  # Отримати фільтр по типу клієнта
    
    db = get_db()  # Отримати з'єднання з БД
    
    if search_query or client_type:  # Якщо є фільтри
        query = "SELECT * FROM clients WHERE 1=1"  # Базовий SELECT
        params = []  # Параметри для безпечного запиту
        
        if search_query:  # Якщо є пошуковий запит
            query += " AND (name LIKE ? OR phone LIKE ?)"  # Шукати по імені або телефону
            params.extend([f"%{search_query}%", f"%{search_query}%"])  # Додати параметри
        
        if client_type and client_type in ['Фізична особа', 'Юридична особа']:  # Якщо вибраний тип правильний
            query += " AND type = ?"  # Фільтр по типу
            params.append(client_type)  # Додати параметр
        
        query += " ORDER BY id DESC"  # Сортування по ID (новіші перші)
        clients = db.execute(query, params).fetchall()  # Виконати запит
    else:  # Якщо немає фільтрів
        clients = db.execute("SELECT * FROM clients ORDER BY id DESC").fetchall()  # Отримати всіх клієнтів

    # Статистика
    stats = {  # Словник зі статистикою
        "total_clients": db.execute("SELECT COUNT(*) FROM clients").fetchone()[0],  # Всього клієнтів
        "physical_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Фізична особа'").fetchone()[0],  # Фізичні особи
        "legal_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Юридична особа'").fetchone()[0],  # Юридичні особи
        "new_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],  # Нові заявки
        "active_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Активна'").fetchone()[0],  # Активні картки
        "total_balance": db.execute("SELECT SUM(balance) FROM cards WHERE currency='UAH'").fetchone()[0] or 0  # Загальний баланс
    }

    return render_template("clients.html",  # Вивести шаблон
                         clients=clients,  # Передати список клієнтів
                         stats=stats,  # Передати статистику
                         search_query=search_query,  # Передати пошуковий запит
                         client_type=client_type)  # Передати вибраний тип

@app.route("/add-client", methods=["GET", "POST"])  # Маршрут додавання клієнта
@login_required  # Потребує авторизації
def add_client():  # Функція додавання клієнта
    if request.method == "POST":  # Якщо форма відправлена
        name = sanitize_input(request.form.get("name"))  # Отримати й очистити ім'я
        phone = sanitize_input(request.form.get("phone"))  # Отримати й очистити телефон
        client_type = sanitize_input(request.form.get("type"))  # Отримати й очистити тип клієнта
        
        # Валідація
        errors = []  # Список помилок
        if not validate_name(name):  # Якщо ім'я невалідне
            errors.append("ПІБ має містити мінімум 2 символи і лише літери")  # Додати помилку
        
        if not validate_phone(phone):  # Якщо телефон невалідний
            errors.append("Невірний формат телефону. Формат: +380XXXXXXXXX")  # Додати помилку
        
        if client_type not in ["Фізична особа", "Юридична особа"]:  # Якщо тип невалідний
            errors.append("Невірний тип клієнта")  # Додати помилку
        
        if errors:  # Якщо є помилки
            for error in errors:  # Для кожної помилки
                flash(error, "error")  # Показати помилку
            return render_template("add_clients.html")  # Повернути форму
        
        db = get_db()  # Отримати з'єднання з БД
        
        # Перевірка дублікату телефону
        existing = db.execute("SELECT id FROM clients WHERE phone = ?", (phone,)).fetchone()  # Шукати клієнта з таким телефоном
        if existing:  # Якщо клієнт існує
            flash(f"❌ Клієнт з телефоном {phone} вже існує в системі", "error")  # Помилка
            return render_template("add_clients.html")  # Повернути форму
        
        try:  # Спроба додавання
            cursor = db.execute(  # Вставити новий клієнта
                "INSERT INTO clients (name, phone, type) VALUES (?, ?, ?)",
                (name, phone, client_type)  # Параметри
            )
            db.commit()  # Збереження змін
            
            client_id = cursor.lastrowid  # Отримати ID нового клієнта
            log_action(session['user'], f"Додано клієнта: {name} (ID: {client_id})",  # Залогувати
                      table_name='clients', record_id=client_id, ip_address=request.remote_addr)
            create_notification(session['user'], f"Клієнта {name} успішно додано!", "success")  # Нотифікація
            
            flash(f"✅ Клієнта {name} успішно додано!", "success")  # Повідомлення про успіх
            return redirect(f"/client/{client_id}")  # Перенаправити на профіль клієнта
        except Exception as e:  # При помилці
            flash("❌ Помилка при додаванні клієнта", "error")  # Помилка
            print(f"Error: {e}")  # Вивести помилку в консоль

    return render_template("add_clients.html")  # Показати форму додавання

@app.route("/edit-client/<int:client_id>", methods=["GET", "POST"])  # Маршрут редагування клієнта
@login_required  # Потребує авторизації
def edit_client(client_id):  # Функція редагування клієнта
    db = get_db()  # Отримати з'єднання з БД

    if request.method == "POST":  # Якщо форма відправлена
        name = sanitize_input(request.form.get("name"))  # Отримати й очистити ім'я
        phone = sanitize_input(request.form.get("phone"))  # Отримати й очистити телефон
        client_type = sanitize_input(request.form.get("type"))  # Отримати й очистити тип
        
        # Валідація
        errors = []  # Список помилок
        if not validate_name(name):  # Якщо ім'я невалідне
            errors.append("ПІБ має містити мінімум 2 символи і лише літери")  # Помилка
        
        if not validate_phone(phone):  # Якщо телефон невалідний
            errors.append("Невірний формат телефону")  # Помилка
        
        if errors:  # Якщо є помилки
            for error in errors:  # Для кожної помилки
                flash(error, "error")  # Показати
            return redirect(f"/edit-client/{client_id}")  # Повернути на редагування
        
        # Перевірка дублікату телефону (окрім поточного клієнта)
        existing = db.execute(  # Шукати іншого клієнта з таким телефоном
            "SELECT id FROM clients WHERE phone = ? AND id != ?", 
            (phone, client_id)  # Окрім поточного ID
        ).fetchone()
        
        if existing:  # Якщо знайдено
            flash(f"❌ Телефон {phone} вже використовується іншим клієнтом", "error")  # Помилка
            return redirect(f"/edit-client/{client_id}")  # Повернути на редагування
        
        try:  # Спроба оновлення
            db.execute(  # Оновити дані клієнта
                "UPDATE clients SET name=?, phone=?, type=? WHERE id=?",
                (name, phone, client_type, client_id)  # Параметри
            )
            db.commit()  # Збереження змін
            
            log_action(session['user'], f"Оновлено клієнта: {name} (ID: {client_id})",  # Залогувати
                      table_name='clients', record_id=client_id, ip_address=request.remote_addr)
            
            flash("✅ Дані клієнта успішно оновлено!", "success")  # Успіх
            return redirect(f"/client/{client_id}")  # Перенаправити на профіль
        except Exception as e:  # При помилці
            flash("❌ Помилка при оновленні даних", "error")  # Помилка
            print(f"Error: {e}")  # Вивести в консоль

    client = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()  # Отримати дані клієнта
    
    if not client:  # Якщо клієнта немає
        flash("❌ Клієнта не знайдено", "error")  # Помилка
        return redirect("/clients")  # На сторінку клієнтів

    return render_template("edit_client.html", client=client)  # Показати форму редагування

@app.route("/delete-client/<int:client_id>")  # Маршрут видалення клієнта
@login_required  # Потребує авторизації
def delete_client(client_id):  # Функція видалення клієнта
    db = get_db()  # Отримати з'єднання з БД
    
    client = db.execute("SELECT name FROM clients WHERE id=?", (client_id,)).fetchone()  # Отримати ім'я клієнта
    
    if not client:  # Якщо клієнта немає
        flash("❌ Клієнта не знайдено", "error")  # Помилка
        return redirect("/clients")  # На сторінку клієнтів
    
    try:  # Спроба видалення
        db.execute("DELETE FROM clients WHERE id=?", (client_id,))  # Видалити клієнта
        db.commit()  # Збереження змін
        
        log_action(session['user'], f"Видалено клієнта: {client['name']} (ID: {client_id})",  # Залогувати
                  table_name='clients', record_id=client_id, ip_address=request.remote_addr)
        
        flash(f"✅ Клієнта {client['name']} та всі пов'язані дані видалено", "success")  # Успіх
    except Exception as e:  # При помилці
        flash("❌ Помилка при видаленні клієнта", "error")  # Помилка
        print(f"Error: {e}")  # Вивести в консоль
    
    return redirect("/clients")  # На сторінку клієнтів

# ========== PROFILE ==========
@app.route("/client/<int:client_id>")  # Маршрут профілю клієнта
@login_required  # Потребує авторизації
def client_profile(client_id):  # Функція профілю клієнта
    db = get_db()  # Отримати з'єднання з БД
    client = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()  # Отримати клієнта
    
    if not client:  # Якщо клієнта немає
        flash("❌ Клієнта не знайдено", "error")  # Помилка
        return redirect("/clients")  # На сторінку клієнтів
    
    cards = db.execute(  # Отримати картки клієнта
        "SELECT * FROM cards WHERE client_id=? ORDER BY created_at DESC",
        (client_id,)  # Для даного клієнта
    ).fetchall()
    
    # Отримання транзакцій для графіка
    transactions = db.execute("""  # Отримати транзакції картки
        SELECT t.*, c.currency 
        FROM transactions t
        JOIN cards c ON t.card_id = c.id
        WHERE c.client_id = ?
        ORDER BY t.created_at DESC
        LIMIT 50  # Останні 50 транзакцій
    """, (client_id,)).fetchall()

    rating = (  # Рейтинг клієнта залежно від типу
        {"label": "TRUSTED", "class": "rating-green", "score": 95}  # Юридичні особи
        if client["type"] == "Юридична особа"
        else {"label": "STANDARD", "class": "rating-yellow", "score": 75}  # Фізичні особи
    )

    return render_template(  # Показати шаблон профілю
        "client_profile.html",  # Файл шаблону
        client=client,  # Дані клієнта
        cards=cards,  # Картки клієнта
        rating=rating,  # Рейтинг клієнта
        transactions=transactions  # Транзакції картки
    )

@app.route("/issue-card/<int:client_id>/<currency>")  # Маршрут видачі карти
@login_required  # Потребує авторизації
def issue_card(client_id, currency):  # Функція видачі картки
    if currency not in ['UAH', 'USD', 'EUR']:  # Якщо валюта невалідна
        flash("❌ Невірна валюта", "error")  # Помилка
        return redirect(f"/client/{client_id}")  # На профіль клієнта
    
    db = get_db()  # Отримати з'єднання з БД

    count = db.execute(  # Отримати кількість карток клієнта
        "SELECT COUNT(*) FROM cards WHERE client_id=?",
        (client_id,)  # Для даного клієнта
    ).fetchone()[0]

    if count >= 3:  # Якщо вже 3 або більше карток
        flash("❌ Досягнуто ліміт карток (максимум 3)", "warning")  # Попередження
        return redirect(f"/client/{client_id}")  # На профіль клієнта

    exists = db.execute(  # Перевірити чи існує картка цієї валюти
        "SELECT 1 FROM cards WHERE client_id=? AND currency=?",
        (client_id, currency)  # Для даного клієнта і валюти
    ).fetchone()

    if exists:  # Якщо такі картка існує
        flash(f"❌ У клієнта вже є картка в {currency}", "warning")  # Попередження
        return redirect(f"/client/{client_id}")  # На профіль клієнта

    # Генерація номера картки
    number = f"4441 {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"  # Випадковий номер
    balance = 1000.0 if currency == "UAH" else 100.0 if currency == "USD" else 50.0  # Початковий баланс

    try:  # Спроба створення картки
        cursor = db.execute(  # Вставити нову картку
            "INSERT INTO cards (client_id, card_number, balance, currency) VALUES (?, ?, ?, ?)",
            (client_id, number, balance, currency)  # Параметри
        )
        card_id = cursor.lastrowid  # Отримати ID нової картки
        
        # Логування початкового балансу
        db.execute(  # Вставити транзакцію початкового балансу
            "INSERT INTO transactions (card_id, amount, type, description) VALUES (?, ?, 'Поповнення', 'Початковий баланс')",
            (card_id, balance)  # Параметри
        )
        db.commit()  # Збереження змін
        
        log_action(session['user'], f"Емітовано картку {currency} (ID: {card_id})",  # Залогувати
                  table_name='cards', record_id=card_id, ip_address=request.remote_addr)
        
        flash(f"✅ Картку {currency} успішно створено! Номер: {number}", "success")  # Успіх
    except Exception as e:  # При помилці
        flash("❌ Помилка при створенні картки", "error")  # Помилка
        print(f"Error: {e}")  # Вивести в консоль

    return redirect(f"/client/{client_id}")  # На профіль клієнта

@app.route("/toggle-card/<int:card_id>")  # Маршрут блокування/розблокування картки
@login_required  # Потребує авторизації
def toggle_card(card_id):  # Функція змінення статусу картки
    db = get_db()  # Отримати з'єднання з БД
    card = db.execute("SELECT * FROM cards WHERE id=?", (card_id,)).fetchone()  # Отримати картку

    if card:  # Якщо картка існує
        new_status = "Заблокована" if card["status"] == "Активна" else "Активна"  # Змінити статус
        db.execute("UPDATE cards SET status=? WHERE id=?", (new_status, card_id))  # Оновити в БД
        db.commit()  # Збереження змін
        
        status_msg = "заблоковано" if new_status == "Заблокована" else "розблоковано"  # Текст для логу
        log_action(session['user'], f"Картку {card['card_number']} {status_msg}",  # Залогувати
                  table_name='cards', record_id=card_id, ip_address=request.remote_addr)
        
        flash(f"✅ Картку успішно {status_msg}", "success")  # Успіх

    return redirect(f"/client/{card['client_id']}")  # На профіль клієнта

# ========== REQUESTS ==========
@app.route("/requests")  # Маршрут списку заявок
@login_required  # Потребує авторизації
def requests_page():  # Функція сторінки заявок
    status_filter = request.args.get('status', '')  # Отримати фільтр по статусу
    
    db = get_db()  # Отримати з'єднання з БД
    
    if status_filter and status_filter in ['Нова', 'В обробці', 'Закрита']:  # Якщо фільтр правильний
        reqs = db.execute("""  # Отримати заявки з фільтром
            SELECT requests.*, clients.name AS client_name
            FROM requests
            JOIN clients ON requests.client_id = clients.id
            WHERE requests.status = ?
            ORDER BY requests.created_at DESC
        """, (status_filter,)).fetchall()  # За статусом
    else:  # Якщо фільтра немає
        reqs = db.execute("""  # Отримати всі заявки
            SELECT requests.*, clients.name AS client_name
            FROM requests
            JOIN clients ON requests.client_id = clients.id
            ORDER BY requests.created_at DESC
        """).fetchall()
    
    # Статистика заявок
    stats = {  # Словник зі статистикою
        "total": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],  # Всього заявок
        "new": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],  # Нових
        "processing": db.execute("SELECT COUNT(*) FROM requests WHERE status='В обробці'").fetchone()[0],  # В обробці
        "closed": db.execute("SELECT COUNT(*) FROM requests WHERE status='Закрита'").fetchone()[0]  # Закритих
    }
    
    return render_template("requests.html", requests=reqs, status_filter=status_filter, stats=stats)  # Показати шаблон

@app.route("/add-request", methods=["GET", "POST"])  # Маршрут додавання заявки
@login_required  # Потребує авторизації
def add_request():  # Функція додавання заявки
    db = get_db()  # Отримати з'єднання з БД

    if request.method == "POST":  # Якщо форма відправл��на
        client_id = request.form.get("client_id")  # Отримати ID клієнта
        service = sanitize_input(request.form.get("service"))  # Отримати й очистити назву послуги
        
        if not validate_name(service):  # Якщо назва послуги невалідна
            flash("❌ Назва послуги має містити лише літери", "error")  # Помилка
            return redirect("/add-request")  # На сторінку додавання
        
        try:  # Спроба створення заявки
            cursor = db.execute(  # Вставити нову заявку
                "INSERT INTO requests (client_id, service, status) VALUES (?, ?, 'Нова')",
                (client_id, service)  # Параметри
            )
            db.commit()  # Збереження змін
            
            request_id = cursor.lastrowid  # Отримати ID заявки
            log_action(session['user'], f"Створено заявку: {service} (ID: {request_id})",  # Залогувати
                      table_name='requests', record_id=request_id, ip_address=request.remote_addr)
            
            flash("✅ Заявку успішно створено!", "success")  # Успіх
            return redirect("/requests")  # На сторінку заявок
        except Exception as e:  # При помилці
            flash("❌ Помилка при створенні заявки", "error")  # Помилка
            print(f"Error: {e}")  # Вивести в консоль

    clients = db.execute("SELECT * FROM clients ORDER BY name").fetchall()  # Отримати список клієнтів
    return render_template("add_request.html", clients=clients)  # Показати форму

@app.route("/request/<int:req_id>/status")  # Маршрут зміни статусу заявки
@login_required  # Потребує авторизації
def next_status(req_id):  # Функція зміни статусу
    db = get_db()  # Отримати з'єднання з БД
    req = db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()  # Отримати заявку

    if req:  # Якщо заявка існує
        status_flow = {  # Словник переходів статусів
            "Нова": "В обробці",  # Нова -> В обробці
            "В обробці": "Закрита"  # В обробці -> Закрита
        }
        new_status = status_flow.get(req["status"], req["status"])  # Отримати новий статус
        
        db.execute("UPDATE requests SET status=? WHERE id=?", (new_status, req_id))  # Оновити статус
        db.commit()  # Збереження змін
        
        log_action(session['user'], f"Змінено статус заявки {req_id}: {req['status']} → {new_status}",  # Залогувати
                  table_name='requests', record_id=req_id, ip_address=request.remote_addr)
        
        flash(f"✅ Статус заявки змінено на '{new_status}'", "success")  # Успіх

    return redirect("/requests")  # На сторінку заявок

@app.route("/about")  # Маршрут сторінки "Про нас"
@login_required  # Потребує авторизації
def about_page():  # Функція сторінки про
    return render_template("about.html")  # Показати шаблон

# ========== API & EXPORT ==========
@app.route("/api/stats")  # API маршрут для статистики
@login_required  # Потребує авторизації
def api_stats():  # Функція API статистики
    """API для отримання статистики"""
    db = get_db()  # Отримати з'єднання з БД
    stats = {  # Словник зі статистикою
        "total_clients": db.execute("SELECT COUNT(*) FROM clients").fetchone()[0],  # Всього клієнтів
        "total_cards": db.execute("SELECT COUNT(*) FROM cards").fetchone()[0],  # Всього карток
        "active_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Активна'").fetchone()[0],  # Активних карток
        "total_requests": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],  # Всього заявок
        "new_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],  # Нових заявок
        "total_balance_uah": db.execute("SELECT SUM(balance) FROM cards WHERE currency='UAH'").fetchone()[0] or 0,  # Баланс в UAH
        "total_balance_usd": db.execute("SELECT SUM(balance) FROM cards WHERE currency='USD'").fetchone()[0] or 0,  # Баланс в USD
        "total_balance_eur": db.execute("SELECT SUM(balance) FROM cards WHERE currency='EUR'").fetchone()[0] or 0  # Баланс в EUR
    }
    return jsonify(stats)  # Повернути JSON

@app.route("/export/clients")  # Маршрут експорту клієнтів
@login_required  # Потребує авторизації
def export_clients():  # Функція експорту
    """Експорт клієнтів у CSV"""
    db = get_db()  # Отримати з'єднання з БД
    clients = db.execute("SELECT * FROM clients ORDER BY id").fetchall()  # Отримати всіх клієнтів
    
    # Створення CSV
    output = "ID,ПІБ,Телефон,Тип,Дата реєстрації\n"  # CSV заголовок
    for c in clients:  # Для кожного клієнта
        output += f"{c['id']},{c['name']},{c['phone']},{c['type']},{c['created_at']}\n"  # Додати рядок
    
    response = make_response(output)  # Створити відповідь
    response.headers["Content-Disposition"] = f"attachment; filename=clients_{datetime.now().strftime('%Y%m%d')}.csv"  # Ім'я файлу
    response.headers["Content-Type"] = "text/csv; charset=utf-8"  # Тип контенту
    
    log_action(session['user'], "Експортовано список клієнтів", ip_address=request.remote_addr)  # Залогувати
    
    return response  # Повернути файл

@app.route("/card/<int:card_id>/qr")  # Маршрут для QR-коду картки
@login_required  # Потребує авторизації
def generate_card_qr(card_id):  # Функція генерації QR
    """Генерація QR-коду для картки"""
    db = get_db()  # Отримати з'єднання з БД
    card = db.execute("SELECT card_number, currency FROM cards WHERE id=?", (card_id,)).fetchone()  # Отримати дані картки
    
    if not card:  # Якщо картки немає
        return jsonify({"error": "Card not found"}), 404  # Помилка 404
    
    # Створення QR-коду
    qr = qrcode.QRCode(version=1, box_size=10, border=2)  # Ініціалізація генератора QR
    qr.add_data(f"CRYSTALBANK:{card['currency']}:{card['card_number']}")  # Додати дані для QR
    qr.make(fit=True)  # Створити QR-код
    
    img = qr.make_image(fill_color="#38bdf8", back_color="white")  # Створити зображення
    buffer = BytesIO()  # Буфер для зображення
    img.save(buffer, format='PNG')  # Зберегти як PNG
    buffer.seek(0)  # На початок буфера
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()  # Закодувати в base64
    
    return jsonify({"qr": f"data:image/png;base64,{qr_base64}"})  # Повернути QR в JSON

@app.route("/backup")  # Маршрут для резервної копії
@login_required  # Потребує авторизації
def create_backup():  # Функція створення резервної копії
    """Створення резервної копії БД (тільки для адмінів)"""
    if session.get('role') != 'admin':  # Якщо користувач не адмін
        flash("❌ Доступ заборонено. Тільки для адміністраторів.", "error")  # Помилка доступу
        return redirect("/clients")  # На сторінку клієнтів
    
    try:  # Спроба створення резервної копії
        backup_path = backup_database()  # Створити резервну копію
        log_action(session['user'], f"Створено резервну копію: {backup_path}", ip_address=request.remote_addr)  # Залогувати
        flash(f"✅ Резервна копія створена: {backup_path}", "success")  # Успіх
    except Exception as e:  # При помилці
        flash(f"❌ Помилка створення резервної копії: {str(e)}", "error")  # Помилка
    
    return redirect("/clients")  # На сторінку клієнтів

# ========== NOTIFICATIONS ==========
@app.route("/notifications")  # Маршрут для отримання нотифікацій
@login_required  # Потребує авторизації
def get_notifications():  # Функція отримання нотифікацій
    """Отримання нотифікацій користувача"""
    db = get_db()  # Отримати з'єднання з БД
    notifications = db.execute(  # Отримати нотифікації
        "SELECT * FROM notifications WHERE user=? ORDER BY created_at DESC LIMIT 10",
        (session['user'],)  # Для поточного користувача, останні 10
    ).fetchall()
    
    return jsonify([dict(n) for n in notifications])  # Повернути як JSON

@app.route("/notifications/mark-read/<int:notif_id>", methods=["POST"])  # Маршрут позначення прочитаною
@login_required  # Потребує авторизації
def mark_notification_read(notif_id):  # Функція позначення
    """Позначити нотифікацію як прочитану"""
    db = get_db()  # Отримати з'єднання з БД
    db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user=?",  # Оновити статус
              (notif_id, session['user']))  # Для даної нотифікації і користувача
    db.commit()  # Збереження змін
    return jsonify({"success": True})  # Повернути успіх

if __name__ == "__main__":  # Якщо файл запущений як основна програма
    app.run(debug=True, host='0.0.0.0', port=5000)  # Запустити сервер (debug=True, будь-який хост, порт 5000)
