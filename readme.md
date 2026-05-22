# Система аутентификации и авторизации

Собственная реализация backend-приложения для аутентификации и авторизации пользователей.

## Структура

auth-system/

├── main.py           # ~200 строк, сервер и API

├── database.py       # ~170 строк, модуль работы с БД

├── auth.db           # БД sqlite3

├── requirements.txt  # зависимости

├── README.md         # документация

├── .gitignore        # игнорируемые файлы

└── LICENSE           # лицензия MIT

## Технологии

- **FastAPI** - веб-фреймворк
- **SQLite3** - встроенная база данных
- **JWT** - токены для аутентификации
- **bcrypt** - хеширование паролей
- **Uvicorn** - ASGI сервер

## Установка и запуск

```bash
# Клонирование репозитория
git clone https://github.com/goryachev-ml/auth-system.git
cd auth-system

# Установка зависимостей
pip install -r requirements.txt

# Запуск сервера
python main.py
