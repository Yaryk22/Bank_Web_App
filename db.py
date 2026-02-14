# ========== ІМПОРТИ БІБЛІОТЕК ==========
# sqlite3 - робота з SQLite базою даних
import sqlite3

# secrets - генерація криптографічно безпечних випадкових даних
import secrets

# Werkzeug - хешування паролів
from werkzeug.security import generate_password_hash

# datetime - робота з датою та часом
from datetime import datetime

# os - робота з операційною системою (файли, директорії)
import os

# shutil - копіювання та переміщення файлів
import shutil

# cryptography - шифрування даних
from cryptography.fernet import Fernet

# json - робота з JSON файлами
import json

# ========== КОНСТАНТИ ==========
# Ім'я файлу бази даних
DB_NAME = "bank.db"

# Директорія для зберігання резервних копій
BACKUP_DIR = "backups"

# Файл конфігурації з ключем шифрування
CONFIG_FILE = "config.json"

# ========== ШИФРУВАННЯ ДАНИХ ==========

def get_or_create_key():
    """
    Отримання або створення ключа шифрування
    Якщо ключа немає - генерує новий та зберігає в config.json
    Якщо є - завантажує з файлу
    """
    # Перевіряємо чи існує файл конфігурації
    if not os.path.exists(CONFIG_FILE):
        # Генеруємо новий ключ шифрування
        key = Fernet.generate_key()
        
        # Створюємо конфігурацію
        config = {"encryption_key": key.decode()}
        
        # Зберігаємо в JSON файл
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        
        return key
    
    # Завантажуємо існуючий ключ
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        return config["encryption_key"].encode()

# Ініціалізація ключа шифрування при завантаженні модуля
ENCRYPTION_KEY = get_or_create_key()

# Створення об'єкту для шифрування/дешифрування
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """
    Шифрування даних за допомогою Fernet
    Приймає текст, повертає зашифрований текст
    """
    if data is None:
        return None
    # Шифруємо дані та конвертуємо в строку
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """
    Дешифрування даних
    Якщо дані не зашифровані - повертає як є (для зворотної сумісності)
    """
    if encrypted_data is None:
        return None
    try:
        # Намагаємося розшифрувати
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        # Якщо помилка - дані не були зашифровані
        return encrypted_data

# ========== ПІДКЛЮЧЕННЯ ДО БАЗИ ДАНИХ ==========

def get_db():
    """
    Створення та налаштування підключення до SQLite бази даних
    Повертає об'єктConnection з налаштованими параметрами
    """
    # Створюємо підключення до БД (створить файл якщо не існує)
    # check_same_thread=False - дозволяє використання з різних потоків
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    
    # Row factory - дозволяє доступ до колонок по імені (row["name"])
    conn.row_factory = sqlite3.Row
    
    # Увімкнення зовнішніх ключів (для забезпечення цілісності даних)
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Write-Ahead Logging - покращує продуктивність при одночасній роботі
    conn.execute("PRAGMA journal_mode = WAL")
    
    return conn

# ========== ІНІЦІАЛІЗАЦІЯ БАЗИ ДАНИХ ==========

def init_db():
    """
    Ініціалізація структури бази даних
    Створює всі таблиці, індекси, тригери та початкові дані
    Викликається один раз при першому запуску
    """
    print("🚀 Ініціалізація бази даних КристалБанк...")
    
    # Створюємо директорію для резервних копій якщо не існує
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # Використовуємо контекстний менеджер для автоматичного закриття з'єднання
    with get_db() as db:
        
        # ========== ТАБЛИЦЯ СПІВРОБІТНИКІВ ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- Унікальний ідентифікатор
            username TEXT UNIQUE NOT NULL,               -- Логін (унікальний)
            password TEXT NOT NULL,                      -- Хеш пароля
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата створення акаунту
            last_login TIMESTAMP,                        -- Дата останнього входу
            is_active BOOLEAN DEFAULT 1,                 -- Активний чи ні (1=так, 0=ні)
            role TEXT DEFAULT 'operator' CHECK(role IN ('admin', 'operator', 'manager'))  -- Роль
        )""")

        # ========== ТАБЛИЦЯ КЛІЄНТІВ ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- ID клієнта
            name TEXT NOT NULL,                          -- ПІБ клієнта
            phone TEXT NOT NULL UNIQUE,                  -- Телефон (унікальний)
            type TEXT NOT NULL CHECK(type IN ('Фізична особа', 'Юридична особа')),  -- Тип клієнта
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата реєстрації
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP   -- Дата останнього оновлення
        )""")

        # ========== ТАБЛИЦЯ ЗАЯВОК НА ПОСЛУГИ ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- ID заявки
            client_id INTEGER NOT NULL,                  -- ID клієнта (зовнішній ключ)
            service TEXT NOT NULL,                       -- Назва послуги
            status TEXT NOT NULL DEFAULT 'Нова' CHECK(status IN ('Нова', 'В обробці', 'Закрита')),  -- Статус
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата створення
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата оновлення
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE  -- При видаленні клієнта видаляються його заявки
        )""")

        # ========== ТАБЛИЦЯ БАНКІВСЬКИХ КАРТОК ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- ID картки
            client_id INTEGER NOT NULL,                  -- ID клієнта-власника
            card_number TEXT UNIQUE NOT NULL,            -- Номер картки (унікальний)
            balance REAL DEFAULT 0.0 CHECK(balance >= 0),  -- Баланс (не може бути від'ємним)
            currency TEXT DEFAULT 'UAH' CHECK(currency IN ('UAH', 'USD', 'EUR')),  -- Валюта
            status TEXT DEFAULT 'Активна' CHECK(status IN ('Активна', 'Заблокована')),  -- Статус
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата створення
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата оновлення
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE  -- Каскадне видалення
        )""")

        # ========== ТАБЛИЦЯ ТРАНЗАКЦІЙ ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- ID транзакції
            card_id INTEGER NOT NULL,                    -- ID картки
            amount REAL NOT NULL,                        -- Сума операції
            type TEXT NOT NULL CHECK(type IN ('Поповнення', 'Зняття', 'Переказ')),  -- Тип операції
            description TEXT,                            -- Опис операції
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Дата та час операції
            FOREIGN KEY (card_id) REFERENCES cards (id) ON DELETE CASCADE  -- Видалення каскадом
        )""")

        # ========== ТАБЛИЦЯ ЛОГІВ (ЖУРНАЛ АУДИТУ) ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- ID запису логу
            user TEXT,                                   -- Користувач який виконав дію
            action TEXT NOT NULL,                        -- Опис дії
            table_name TEXT,                             -- Назва таблиці (якщо застосовно)
            record_id INTEGER,                           -- ID запису (якщо застосовно)
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Час дії
            ip_address TEXT                              -- IP адреса користувача
        )""")

        # ========== ТАБЛИЦЯ НОТИФІКАЦІЙ ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- ID повідомлення
            user TEXT NOT NULL,                          -- Користувач-отримувач
            message TEXT NOT NULL,                       -- Текст повідомлення
            type TEXT DEFAULT 'info' CHECK(type IN ('success', 'error', 'warning', 'info')),  -- Тип
            is_read BOOLEAN DEFAULT 0,                   -- Прочитано (0=ні, 1=так)
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Час створення
        )""")

        # ========== ТАБЛИЦЯ НАЛАШТУВАНЬ СИСТЕМИ ==========
        db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,        -- ID налаштування
            key TEXT UNIQUE NOT NULL,                    -- Ключ (унікальний ідентифікатор)
            value TEXT,                                  -- Значення
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Час оновлення
        )""")

        # ========== СТВОРЕННЯ ІНДЕКСІВ ДЛЯ ПРИСКОРЕННЯ ЗАПИТІВ ==========
        indexes = [
            # Індекси для таблиці clients
            "CREATE INDEX IF NOT EXISTS idx_clients_phone ON clients(phone)",      # Пошук по телефону
            "CREATE INDEX IF NOT EXISTS idx_clients_type ON clients(type)",        # Фільтр по типу
            "CREATE INDEX IF NOT EXISTS idx_clients_created ON clients(created_at)",  # Сортування по даті
            
            # Індекси для таблиці cards
            "CREATE INDEX IF NOT EXISTS idx_cards_client ON cards(client_id)",     # Пошук карток клієнта
            "CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status)",        # Фільтр по статусу
            "CREATE INDEX IF NOT EXISTS idx_cards_currency ON cards(currency)",    # Фільтр по валюті
            
            # Індекси для таблиці requests
            "CREATE INDEX IF NOT EXISTS idx_requests_client ON requests(client_id)",  # Заявки клієнта
            "CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status)",     # Фільтр по статусу
            "CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at)", # Сортування
            
            # Індекси для таблиці transactions
            "CREATE INDEX IF NOT EXISTS idx_transactions_card ON transactions(card_id)",  # Транзакції картки
            "CREATE INDEX IF NOT EXISTS idx_transactions_created ON transactions(created_at)",  # Сортування
            
            # Індекси для таблиці audit_log
            "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user)",        # Пошук по користувачу
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",  # Сортування по часу
            
            # Індекси для таблиці notifications
            "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user)",  # Пошук по користувачу
            "CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read)"  # Фільтр прочитаних
        ]
        
        # Створюємо всі індекси
        for index in indexes:
            db.execute(index)

        # ========== СТВОРЕННЯ ТРИГЕРІВ ==========
        # Тригери автоматично оновлюють поле updated_at при зміні записів
        
        triggers = [
            # Тригер для таблиці clients
            """
            CREATE TRIGGER IF NOT EXISTS update_clients_timestamp 
            AFTER UPDATE ON clients
            BEGIN
                UPDATE clients SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            """,
            
            # Тригер для таблиці requests
            """
            CREATE TRIGGER IF NOT EXISTS update_requests_timestamp 
            AFTER UPDATE ON requests
            BEGIN
                UPDATE requests SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            """,
            
            # Тригер для таблиці cards
            """
            CREATE TRIGGER IF NOT EXISTS update_cards_timestamp 
            AFTER UPDATE ON cards
            BEGIN
                UPDATE cards SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            """
        ]
        
        # Створюємо всі тригери
        for trigger in triggers:
            db.execute(trigger)

        # ========== СТВОРЕННЯ АДМІНІСТРАТОРА ==========
        # Перевіряємо чи існує адміністратор
        existing_admin = db.execute(
            "SELECT id FROM employees WHERE username = 'admin'"
        ).fetchone()

        if not existing_admin:
            # Хешуємо пароль (ВАЖЛИВО: змінити на продакшені!)
            admin_password = generate_password_hash("admin123")
            
            # Створюємо адміністратора
            db.execute(
                "INSERT INTO employees (username, password, role) VALUES (?, ?, ?)",
                ("admin", admin_password, "admin")
            )
            print("✅ Адміністратора створено: admin / admin123")
            print("⚠️  ВАЖЛИВО: Змініть пароль адміністратора!")
        else:
            print("ℹ️  Адміністратор вже існує")

        # ========== ПОЧАТКОВІ НАЛАШТУВАННЯ СИСТЕМИ ==========
        settings_defaults = [
            ("max_cards_per_client", "3"),              # Максимум карток на клієнта
            ("default_currency", "UAH"),                 # Валюта за замовчуванням
            ("backup_enabled", "1"),                     # Увімкнено резервне копіювання
            ("backup_interval_hours", "24"),             # Інтервал бекапів (години)
            ("session_timeout_minutes", "30")            # Таймаут сесії (хвилини)
        ]
        
        # Додаємо налаштування якщо їх ще немає
        for key, value in settings_defaults:
            existing = db.execute("SELECT id FROM settings WHERE key=?", (key,)).fetchone()
            if not existing:
                db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))

        # ========== СТВОРЕННЯ ТЕСТОВИХ ДАНИХ ==========
        # Для розробки та тестування
        create_sample_data(db)

        # Зберігаємо всі зміни в БД
        db.commit()
        print("✅ База даних успішно ініціалізована!")

# ========== СТВОРЕННЯ ТЕСТОВИХ ДАНИХ ==========

def create_sample_data(db):
    """
    Створення тестових даних для розробки
    Додає співробітників, клієнтів, картки та заявки
    Викликається тільки при першому запуску (якщо БД порожня)
    """
    # Перевіряємо чи є вже клієнти
    client_count = db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    
    if client_count > 0:
        print("ℹ️  Тестові дані вже існують")
        return

    print("📝 Створення тестових даних...")

    # ========== ДОДАВАННЯ СПІВРОБІТНИКІВ ==========
    operators = [
        ("operator1", generate_password_hash("1234"), "operator"),  # Оператор
        ("manager1", generate_password_hash("1234"), "manager")     # Менеджер
    ]
    
    for username, password, role in operators:
        db.execute(
            "INSERT INTO employees (username, password, role) VALUES (?, ?, ?)",
            (username, password, role)
        )

    # ========== ДОДАВАННЯ КЛІЄНТІВ ==========
    test_clients = [
        ("Полецький Максим Іванович", "+380501234567", "Фізична особа"),
        ("Олійник Олександр", "+380672345678", "Фізична особа"),
        ("Сидоренко Олена Михайлівна", "+380933456789", "Фізична особа"),
        ("ТОВ 'КРИСТАЛ ГРУП'", "+380443456789", "Юридична особа"),
        ("ПП 'ТЕХНОБУД'", "+380445678901", "Юридична особа"),
    ]

    for name, phone, client_type in test_clients:
        db.execute(
            "INSERT INTO clients (name, phone, type) VALUES (?, ?, ?)",
            (name, phone, client_type)
        )

    # ========== ДОДАВАННЯ КАРТОК ==========
    import random
    
    # Отримуємо всіх клієнтів
    clients = db.execute("SELECT id FROM clients").fetchall()
    
    # Доступні валюти
    currencies = ['UAH', 'USD', 'EUR']
    
    for client in clients:
        # Кожен клієнт отримає 1-2 картки (випадково)
        num_cards = random.randint(1, 2)
        used_currencies = []  # Щоб не повторювати валюту

        for _ in range(num_cards):
            # Вибираємо валюту яку ще не використовували
            available = [c for c in currencies if c not in used_currencies]
            if not available:
                break  # Якщо всі валюти використані
            
            currency = random.choice(available)
            used_currencies.append(currency)
            
            # Генеруємо номер картки (формат Visa: 4441 XXXX XXXX XXXX)
            card_number = f"4441 {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
            
            # Випадковий баланс залежно від валюти
            if currency == 'UAH':
                balance = random.randint(1000, 50000)     # 1000-50000 грн
            elif currency == 'USD':
                balance = random.randint(100, 5000)       # 100-5000 дол
            else:
                balance = random.randint(50, 2000)        # 50-2000 євро
            
            # Створюємо картку
            cursor = db.execute(
                "INSERT INTO cards (client_id, card_number, balance, currency) VALUES (?, ?, ?, ?)",
                (client['id'], card_number, balance, currency)
            )
            
            # Додаємо початкову транзакцію (поповнення балансу)
            db.execute(
                "INSERT INTO transactions (card_id, amount, type, description) VALUES (?, ?, 'Поповнення', 'Початковий баланс')",
                (cursor.lastrowid, balance)
            )

    # ========== ДОДАВАННЯ ЗАЯВОК ==========
    test_requests = [
        (1, "Відкриття депозиту", "Нова"),                            # Нова заявка
        (2, "Оформлення кредиту", "В обробці"),                       # В обробці
        (3, "Розрахунково-касове обслуговування", "Закрита"),         # Закрита
        (1, "Консультація з інвестицій", "Нова"),                     # Нова
        (4, "Відкриття валютного рахунку", "В обробці"),             # В обробці
    ]

    for client_id, service, status in test_requests:
        db.execute(
            "INSERT INTO requests (client_id, service, status) VALUES (?, ?, ?)",
            (client_id, service, status)
        )

    print("✅ Тестові дані створено успішно!")

# ========== ЛОГУВАННЯ ДІЙ (АУДИТ) ==========

def log_action(user, action, table_name=None, record_id=None, ip_address=None):
    """
    Логування дій користувачів для аудиту безпеки
    Записує хто, що, коли та звідки зробив
    
    Параметри:
    - user: логін користувача
    - action: опис дії
    - table_name: назва таблиці (опціонально)
    - record_id: ID запису (опціонально)
    - ip_address: IP адреса (опціонально)
    """
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO audit_log (user, action, table_name, record_id, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user, action, table_name, record_id, ip_address)
            )
            db.commit()
    except Exception as e:
        # Якщо логування не вдалося - не ламаємо основний функціонал
        print(f"⚠️  Помилка логування: {e}")

def cleanup_old_logs(days=90):
    """
    Очищення старих логів для економії місця
    Видаляє записи старші за вказану кількість днів
    
    Параметри:
    - days: кількість днів (за замовчуванням 90)
    """
    with get_db() as db:
        # Видаляємо старі логи аудиту
        deleted = db.execute(
            "DELETE FROM audit_log WHERE timestamp < datetime('now', '-{} days')".format(days)
        ).rowcount
        
        # Видаляємо прочитані нотифікації старші 30 днів
        db.execute(
            "DELETE FROM notifications WHERE is_read=1 AND created_at < datetime('now', '-30 days')"
        )
        
        db.commit()
        print(f"✅ Видалено {deleted} старих записів логів")

# ========== СТАТИСТИКА БАЗИ ДАНИХ ==========

def get_db_stats():
    """
    Збір статистики бази даних
    Повертає словник з різними метриками
    """
    with get_db() as db:
        stats = {
            # Загальна кількість клієнтів
            "clients": db.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
            
            # Кількість фізичних осіб
            "physical_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Фізична особа'").fetchone()[0],
            
            # Кількість юридичних осіб
            "legal_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Юридична особа'").fetchone()[0],
            
            # Всього карток
            "cards": db.execute("SELECT COUNT(*) FROM cards").fetchone()[0],
            
            # Активних карток
            "active_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Активна'").fetchone()[0],
            
            # Заблокованих карток
            "blocked_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Заблокована'").fetchone()[0],
            
            # Всього заявок
            "requests": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
            
            # Нових заявок
            "new_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],
            
            # Заявок в обробці
            "processing_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='В обробці'").fetchone()[0],
            
            # Закритих заявок
            "closed_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Закрита'").fetchone()[0],
            
            # Сумарний баланс в гривнях
            "total_balance_uah": db.execute("SELECT SUM(balance) FROM cards WHERE currency='UAH'").fetchone()[0] or 0,
            
            # Сумарний баланс в доларах
            "total_balance_usd": db.execute("SELECT SUM(balance) FROM cards WHERE currency='USD'").fetchone()[0] or 0,
            
            # Сумарний баланс в євро
            "total_balance_eur": db.execute("SELECT SUM(balance) FROM cards WHERE currency='EUR'").fetchone()[0] or 0,
            
            # Всього транзакцій
            "total_transactions": db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0],
            
            # Розмір файлу БД в мегабайтах
            "db_size_mb": os.path.getsize(DB_NAME) / (1024 * 1024) if os.path.exists(DB_NAME) else 0
        }
    return stats

# ========== РЕЗЕРВНЕ КОПІЮВАННЯ ==========

def backup_database(backup_path=None):
    """
    Створення резервної копії бази даних
    Копіює файл БД у директорію backups з міткою часу
    
    Параметри:
    - backup_path: шлях для збереження (опціонально)
    
    Повертає: шлях до створеного бекапу
    """
    if backup_path is None:
        # Генеруємо ім'я файлу з поточною датою та часом
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"bank_backup_{timestamp}.db")
    
    try:
        # Копіюємо файл БД
        shutil.copy2(DB_NAME, backup_path)
        
        # ========== ОБМЕЖЕННЯ КІЛЬКОСТІ БЕКАПІВ ==========
        # Отримуємо список всіх бекапів
        backups = sorted([
            os.path.join(BACKUP_DIR, f) 
            for f in os.listdir(BACKUP_DIR) 
            if f.startswith('bank_backup_')
        ])
        
        # Зберігаємо тільки останні 10 бекапів
        while len(backups) > 10:
            oldest = backups.pop(0)  # Беремо найстаріший
            os.remove(oldest)         # Видаляємо
            print(f"🗑️  Видалено старий бекап: {oldest}")
        
        print(f"✅ Резервна копія створена: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Помилка створення резервної копії: {e}")
        raise

def restore_database(backup_path):
    """
    Відновлення бази даних з резервної копії
    Спочатку створює бекап поточної БД (на всяк випадок)
    
    Параметри:
    - backup_path: шлях до файлу бекапу
    """
    # Перевіряємо чи існує файл бекапу
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Бекап не знайдено: {backup_path}")
    
    try:
        # Створюємо бекап поточної БД перед відновленням (на всяк випадок)
        current_backup = backup_database()
        print(f"📦 Створено бекап поточної БД: {current_backup}")
        
        # Відновлюємо БД з бекапу
        shutil.copy2(backup_path, DB_NAME)
        print(f"✅ База даних відновлена з: {backup_path}")
    except Exception as e:
        print(f"❌ Помилка відновлення: {e}")
        raise

# ========== НАЛАШТУВАННЯ СИСТЕМИ ==========

def get_setting(key, default=None):
    """
    Отримання значення налаштування
    
    Параметри:
    - key: ключ налаштування
    - default: значення за замовчуванням якщо налаштування не знайдено
    
    Повертає: значення налаштування або default
    """
    with get_db() as db:
        result = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return result['value'] if result else default

def set_setting(key, value):
    """
    Збереження налаштування
    Якщо ключ існує - оновлює, якщо ні - створює новий
    
    Параметри:
    - key: ключ налаштування
    - value: значення
    """
    with get_db() as db:
        # INSERT OR REPLACE - оновлює якщо існує, створює якщо немає
        db.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (key, value)
        )
        db.commit()

# ========== АВТОМАТИЗОВАНІ ЗАВДАННЯ ==========

def setup_automated_backup():
    """
    Налаштування автоматичного резервного копіювання
    Використовує планувальник для періодичного виконання завдань
    Викликати при старті додатку
    """
    from apscheduler.schedulers.background import BackgroundScheduler
    
    # Створюємо планувальник задач
    scheduler = BackgroundScheduler()
    
    # Отримуємо інтервал бекапу з налаштувань (за замовчуванням 24 години)
    interval = int(get_setting('backup_interval_hours', 24))
    
    # Додаємо задачу бекапу
    scheduler.add_job(backup_database, 'interval', hours=interval)
    
    # Додаємо задачу очищення логів (кожні 7 днів)
    scheduler.add_job(cleanup_old_logs, 'interval', days=7)
    
    # Запускаємо планувальник
    scheduler.start()
    print(f"⏰ Автоматичний бекап налаштовано (кожні {interval} годин)")

# ========== ГОЛОВНА ФУНКЦІЯ (ТОЧКА ВХОДУ) ==========

if __name__ == "__main__":
    """
    Виконується при прямому запуску файлу (python db.py)
    Ініціалізує БД та виводить статистику
    """
    print("=" * 60)
    print("🏦 КРИСТАЛБАНК - СИСТЕМА УПРАВЛІННЯ ДАНИМИ v2.0")
    print("=" * 60)
    
    # Ініціалізація бази даних
    init_db()
    
    # ========== ВИВЕДЕННЯ СТАТИСТИКИ ==========
    stats = get_db_stats()
    print("\n📊 СТАТИСТИКА БАЗИ ДАНИХ:")
    print(f"   • Всього клієнтів: {stats['clients']} (Фіз: {stats['physical_clients']}, Юр: {stats['legal_clients']})")
    print(f"   • Карток: {stats['cards']} (Активних: {stats['active_cards']}, Заблокованих: {stats['blocked_cards']})")
    print(f"   • Заявок: {stats['requests']} (Нових: {stats['new_requests']}, В обробці: {stats['processing_requests']}, Закритих: {stats['closed_requests']})")
    print(f"   • Транзакцій: {stats['total_transactions']}")
    print(f"   • Баланс UAH: {stats['total_balance_uah']:,.2f} ₴")
    print(f"   • Баланс USD: {stats['total_balance_usd']:,.2f} $")
    print(f"   • Баланс EUR: {stats['total_balance_eur']:,.2f} €")
    print(f"   • Розмір БД: {stats['db_size_mb']:.2f} MB")
    print("\n" + "=" * 60)
    
    # ========== СТВОРЕННЯ ПЕРШОГО БЕКАПУ ==========
    # Перевіряємо чи увімкнено бекапи в налаштуваннях
    if get_setting('backup_enabled', '1') == '1':
        try:
            backup_database()
        except Exception as e:
            print(f"⚠️  Не вдалося створити бекап: {e}")
