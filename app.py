# імпорт бібліотек
import flask
import sqlite3

# Створити екземпляр додатку
app = flask.Flask(__name__)

# Підключення до бази даних
# Встановлює з'єднання з SQLite базою даних
conn = sqlite3.connect('database.db')

# Визначити маршрут для домашньої сторінки
@app.route('/')
def home():
    # Повертає інформацію з бази даних
    cursor = conn.cursor()  
    cursor.execute('SELECT * FROM users')  
    users = cursor.fetchall()  
    return flask.render_template('home.html', users=users)  # Передає дані в шаблон

# Запустити додаток, якщо це головний модуль
if __name__ == '__main__':
    app.run(debug=True)  # Запускає сервер у режимі відладки