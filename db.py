import sqlite3
import secrets
from werkzeug.security import generate_password_hash
from datetime import datetime
import os
import shutil
from cryptography.fernet import Fernet
import json

# Визначаємо назви файлів та директорій для роботи системи
DB_NAME = "bank.db"
BACKUP_DIR = "backups"
CONFIG_FILE = "config.json"

# ========== ШИФРУВАННЯ ==========

def get_or_create_key():
    """Отримання або створення ключа шифрування для захисту конфіденційних даних"""
    # Якщо конфігураційного файлу немає, створюємо новий ключ
    if not os.path.exists(CONFIG_FILE):
        key = Fernet.generate_key()
        config = {"encryption_key": key.decode()}
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        return key
    
    # Якщо файл є, зчитуємо існуючий ключ
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        return config["encryption_key"].encode()

# Ініціалізуємо об'єкт для шифрування
ENCRYPTION_KEY = get_or_create_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Шифрування вхідного рядка"""
    if data is None:
        return None
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Дешифрування даних, якщо вони були зашифровані"""
    if encrypted_data is None:
        return None
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        # Якщо дані не зашифровані (або ключ інший), повертаємо як є
        return encrypted_data

# ========== DATABASE CONNECTION ==========

def get_db():
    """Створення підключення до SQLite з додатковими налаштуваннями продуктивності"""
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    # Дозволяє звертатися до колонок за іменами, а не тільки за індексами
    conn.row_factory = sqlite3.Row
    # Вмикаємо підтримку зовнішніх ключів (Foreign Keys)
    conn.execute("PRAGMA foreign_keys = ON")
    # Режим WAL дозволяє читати та писати в базу одночасно без блокувань
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

# ========== INITIALIZATION ==========

def init_db():
    """Створення структури таблиць, індексів та тригерів КристалБанку"""
    print("🚀 Ініціалізація бази даних КристалБанк...")
    
    # Створюємо папку для резервних копій, якщо вона відсутня
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    with get_db() as db:
        # Таблиця працівників з ролями (адмін, оператор, менеджер)
        db.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            role TEXT DEFAULT 'operator' CHECK(role IN ('admin', 'operator', 'manager'))
        )""")

        # Таблиця клієнтів (фізичні та юридичні особи)
        db.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL CHECK(type IN ('Фізична особа', 'Юридична особа')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # Таблиця банківських заявок клієнтів
        db.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Нова' CHECK(status IN ('Нова', 'В обробці', 'Закрита')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        )""")

        # Таблиця банківських карток з прив'язкою до клієнта
        db.execute("""
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            card_number TEXT UNIQUE NOT NULL,
            balance REAL DEFAULT 0.0 CHECK(balance >= 0),
            currency TEXT DEFAULT 'UAH' CHECK(currency IN ('UAH', 'USD', 'EUR')),
            status TEXT DEFAULT 'Активна' CHECK(status IN ('Активна', 'Заблокована')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
        )""")

        # Таблиця фінансових транзакцій
        db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('Поповнення', 'Зняття', 'Переказ')),
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (card_id) REFERENCES cards (id) ON DELETE CASCADE
        )""")

        # Лог дій для безпеки (аудит)
        db.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT NOT NULL,
            table_name TEXT,
            record_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT
        )""")

        # Система внутрішніх повідомлень/нотифікацій
        db.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info' CHECK(type IN ('success', 'error', 'warning', 'info')),
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # Таблиця для зберігання глобальних конфігурацій системи
        db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # Створення індексів для швидкого пошуку по базі
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_clients_phone ON clients(phone)",
            "CREATE INDEX IF NOT EXISTS idx_clients_type ON clients(type)",
            "CREATE INDEX IF NOT EXISTS idx_clients_created ON clients(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cards_client ON cards(client_id)",
            "CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status)",
            "CREATE INDEX IF NOT EXISTS idx_cards_currency ON cards(currency)",
            "CREATE INDEX IF NOT EXISTS idx_requests_client ON requests(client_id)",
            "CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status)",
            "CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_card ON transactions(card_id)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_created ON transactions(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user)",
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read)"
        ]
        
        for index in indexes:
            db.execute(index)

        # Створення тригерів для автоматичного оновлення дати зміни запису (updated_at)
        triggers = [
            """
            CREATE TRIGGER IF NOT EXISTS update_clients_timestamp 
            AFTER UPDATE ON clients
            BEGIN
                UPDATE clients SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS update_requests_timestamp 
            AFTER UPDATE ON requests
            BEGIN
                UPDATE requests SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS update_cards_timestamp 
            AFTER UPDATE ON cards
            BEGIN
                UPDATE cards SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END
            """
        ]
        
        for trigger in triggers:
            db.execute(trigger)

        # Перевірка наявності адміністратора, якщо немає — створюємо дефолтного
        existing_admin = db.execute(
            "SELECT id FROM employees WHERE username = 'admin'"
        ).fetchone()

        if not existing_admin:
            admin_password = generate_password_hash("admin123")
            db.execute(
                "INSERT INTO employees (username, password, role) VALUES (?, ?, ?)",
                ("admin", admin_password, "admin")
            )
            print("✅ Адміністратора створено: admin / admin123")
            print("⚠️  ВАЖЛИВО: Змініть пароль адміністратора!")
        else:
            print("ℹ️  Адміністратор вже існує")

        # Додавання стандартних налаштувань системи
        settings_defaults = [
            ("max_cards_per_client", "3"),
            ("default_currency", "UAH"),
            ("backup_enabled", "1"),
            ("backup_interval_hours", "24"),
            ("session_timeout_minutes", "30")
        ]
        
        for key, value in settings_defaults:
            existing = db.execute("SELECT id FROM settings WHERE key=?", (key,)).fetchone()
            if not existing:
                db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))

        # Наповнюємо базу тестовими даними (якщо вона порожня)
        create_sample_data(db)

        db.commit()
        print("✅ База даних успішно ініціалізована!")
        # ========== SAMPLE DATA ==========
def create_sample_data(db):
    """Створення набору тестових даних для демонстрації можливостей системи"""
    # Перевіряємо, чи є вже клієнти, щоб не дублювати дані при кожному запуску
    client_count = db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    
    if client_count > 0:
        print("ℹ️  Тестові дані вже існують")
        return

    print("📝 Створення тестових даних...")

    # Додаємо тестових співробітників з різними рівнями доступу
    operators = [
        ("operator1", generate_password_hash("1234"), "operator"),
        ("manager1", generate_password_hash("1234"), "manager")
    ]
    
    for username, password, role in operators:
        db.execute(
            "INSERT INTO employees (username, password, role) VALUES (?, ?, ?)",
            (username, password, role)
        )

    # Список тестових клієнтів (фізособи та компанії)
    test_clients = [
        ("Подлецький Максим Іванович", "+380501234567", "Фізична особа"),
        ("Олійник Олександр ", "+380672345678", "Фізична особа"),
        ("Сидоренко Олена Михайлівна", "+380933456789", "Фізична особа"),
        ("ТОВ 'КРИСТАЛ ГРУП'", "+380443456789", "Юридична особа"),
        ("ПП 'ТЕХНОБУД'", "+380445678901", "Юридична особа"),
    ]

    for name, phone, client_type in test_clients:
        db.execute(
            "INSERT INTO clients (name, phone, type) VALUES (?, ?, ?)",
            (name, phone, client_type)
        )

    # Генерація випадкових карток для кожного клієнта
    import random
    clients = db.execute("SELECT id FROM clients").fetchall()
    
    currencies = ['UAH', 'USD', 'EUR']
    for client in clients:
        # Кожен клієнт отримує 1 або 2 картки в різних валютах
        num_cards = random.randint(1, 2)
        used_currencies = []
        
        for _ in range(num_cards):
            available = [c for c in currencies if c not in used_currencies]
            if not available:
                break
            
            currency = random.choice(available)
            used_currencies.append(currency)
            
            # Генеруємо форматний номер картки
            card_number = f"4441 {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
            
            # Встановлюємо початковий баланс залежно від валюти
            if currency == 'UAH':
                balance = random.randint(1000, 50000)
            elif currency == 'USD':
                balance = random.randint(100, 5000)
            else:
                balance = random.randint(50, 2000)
            
            # Зберігаємо картку в базу
            cursor = db.execute(
                "INSERT INTO cards (client_id, card_number, balance, currency) VALUES (?, ?, ?, ?)",
                (client['id'], card_number, balance, currency)
            )
            
            # Створюємо запис про першу транзакцію (поповнення) для історії
            db.execute(
                "INSERT INTO transactions (card_id, amount, type, description) VALUES (?, ?, 'Поповнення', 'Початковий баланс')",
                (cursor.lastrowid, balance)
            )

    # Додаємо кілька прикладів заявок на банківські послуги
    test_requests = [
        (1, "Відкриття депозиту", "Нова"),
        (2, "Оформлення кредиту", "В обробці"),
        (3, "Розрахунково-касове обслуговування", "Закрита"),
        (1, "Консультація з інвестицій", "Нова"),
        (4, "Відкриття валютного рахунку", "В обробці"),
    ]

    for client_id, service, status in test_requests:
        db.execute(
            "INSERT INTO requests (client_id, service, status) VALUES (?, ?, ?)",
            (client_id, service, status)
        )

    print("✅ Тестові дані створено успішно!")

# ========== LOGGING ==========
def log_action(user, action, table_name=None, record_id=None, ip_address=None):
    """Фіксація дій користувача в таблиці аудиту для безпеки"""
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO audit_log (user, action, table_name, record_id, ip_address) VALUES (?, ?, ?, ?, ?)",
                (user, action, table_name, record_id, ip_address)
            )
            db.commit()
    except Exception as e:
        print(f"⚠️  Помилка логування: {e}")

def cleanup_old_logs(days=90):
    """Автоматичне видалення застарілих записів логів та прочитаних сповіщень"""
    with get_db() as db:
        # Видаляємо логи, старіші за вказану кількість днів
        deleted = db.execute(
            "DELETE FROM audit_log WHERE timestamp < datetime('now', '-{} days')".format(days)
        ).rowcount
        
        # Видаляємо прочитані сповіщення через 30 днів
        db.execute(
            "DELETE FROM notifications WHERE is_read=1 AND created_at < datetime('now', '-30 days')"
        )
        
        db.commit()
        print(f"✅ Видалено {deleted} старих записів логів")

# ========== STATISTICS ==========
def get_db_stats():
    """Збір повної статистики по базі даних для головного екрана"""
    with get_db() as db:
        stats = {
            "clients": db.execute("SELECT COUNT(*) FROM clients").fetchone()[0],
            "physical_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Фізична особа'").fetchone()[0],
            "legal_clients": db.execute("SELECT COUNT(*) FROM clients WHERE type='Юридична особа'").fetchone()[0],
            "cards": db.execute("SELECT COUNT(*) FROM cards").fetchone()[0],
            "active_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Активна'").fetchone()[0],
            "blocked_cards": db.execute("SELECT COUNT(*) FROM cards WHERE status='Заблокована'").fetchone()[0],
            "requests": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
            "new_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Нова'").fetchone()[0],
            "processing_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='В обробці'").fetchone()[0],
            "closed_requests": db.execute("SELECT COUNT(*) FROM requests WHERE status='Закрита'").fetchone()[0],
            "total_balance_uah": db.execute("SELECT SUM(balance) FROM cards WHERE currency='UAH'").fetchone()[0] or 0,
            "total_balance_usd": db.execute("SELECT SUM(balance) FROM cards WHERE currency='USD'").fetchone()[0] or 0,
            "total_balance_eur": db.execute("SELECT SUM(balance) FROM cards WHERE currency='EUR'").fetchone()[0] or 0,
            "total_transactions": db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0],
            "db_size_mb": os.path.getsize(DB_NAME) / (1024 * 1024) if os.path.exists(DB_NAME) else 0
        }
    return stats

# ========== BACKUP ==========
def backup_database(backup_path=None):
    """Створення резервної копії файлу бази даних з ротацією (зберігаємо лише 10 останніх)"""
    if backup_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"bank_backup_{timestamp}.db")
    
    try:
        shutil.copy2(DB_NAME, backup_path)
        
        # Сортуємо існуючі бекапи та видаляємо найстаріші, якщо їх більше 10
        backups = sorted([
            os.path.join(BACKUP_DIR, f) 
            for f in os.listdir(BACKUP_DIR) 
            if f.startswith('bank_backup_')
        ])
        
        while len(backups) > 10:
            oldest = backups.pop(0)
            os.remove(oldest)
            print(f"🗑️  Видалено старий бекап: {oldest}")
        
        print(f"✅ Резервна копія створена: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Помилка створення резервної копії: {e}")
        raise

def restore_database(backup_path):
    """Відновлення бази даних з вибраного файлу бекапу"""
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Бекап не знайдено: {backup_path}")
    
    try:
        # Перед відновленням про всяк випадок робимо бекап поточної (можливо пошкодженої) бази
        current_backup = backup_database()
        print(f"📦 Створено бекап поточної БД перед відновленням: {current_backup}")
        
        shutil.copy2(backup_path, DB_NAME)
        print(f"✅ База даних відновлена з: {backup_path}")
    except Exception as e:
        print(f"❌ Помилка відновлення: {e}")
        raise

# ========== SETTINGS ==========
def get_setting(key, default=None):
    """Отримання значення налаштування з таблиці settings"""
    with get_db() as db:
        result = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return result['value'] if result else default

def set_setting(key, value):
    """Запис або оновлення налаштування в базі даних"""
    with get_db() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (key, value)
        )
        db.commit()

# ========== AUTOMATED TASKS ==========
def setup_automated_backup():
    """Запуск фонових завдань: бекапи та очищення логів за розкладом"""
    from apscheduler.schedulers.background import BackgroundScheduler
    
    scheduler = BackgroundScheduler()
    
    # Визначаємо інтервал бекапів з налаштувань бази
    interval = int(get_setting('backup_interval_hours', 24))
    scheduler.add_job(backup_database, 'interval', hours=interval)
    
    # Очищення логів раз на тиждень
    scheduler.add_job(cleanup_old_logs, 'interval', days=7)
    
    scheduler.start()
    print(f"⏰ Автоматичний бекап налаштовано (кожні {interval} годин)")

# ========== MAIN ==========
if __name__ == "__main__":
    # Головний блок запуску програми
    print("=" * 60)
    print("🏦 КРИСТАЛБАНК - СИСТЕМА УПРАВЛІННЯ ДАНИМИ v2.0")
    print("=" * 60)
    
    # 1. Ініціалізація структури таблиць
    init_db()
    
    # 2. Отримання та вивід аналітики по системі
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
    
    # 3. Створення контрольної точки (бекапу) при запуску, якщо це дозволено налаштуваннями
    if get_setting('backup_enabled', '1') == '1':
        try:
            backup_database()
        except Exception as e:
            print(f"⚠️  Не вдалося створити бекап: {e}")
