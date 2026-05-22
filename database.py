"""
database.py - работа с SQLite3
Все функции для работы с базой данных
"""

import sqlite3
from typing import Optional, Dict, List, Any
 
DATABASE_FILE = "auth.db"

def get_connection():
    """Создает подключение к SQLite базе данных"""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    """Создает все необходимые таблицы"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Таблица пользователей
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Таблица для хранения токенов
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    conn.commit()
    conn.close()

# ========== Пользователи ==========

def create_user(email: str, name: str, password_hash: str, role: str = 'user') -> int:
    """Создает нового пользователя"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO users (email, name, password_hash, role)
        VALUES (?, ?, ?, ?)
    """, (email, name, password_hash, role))
    
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Получает пользователя по email"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Получает пользователя по ID"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    
    conn.close()
    return dict(row) if row else None

def update_user(user_id: int, **kwargs) -> bool:
    """Обновляет поля пользователя"""
    allowed_fields = ['name', 'role']
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    
    if not updates:
        return False
    
    conn = get_connection()
    cursor = conn.cursor()
    
    set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
    values = list(updates.values()) + [user_id]
    
    cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
    conn.commit()
    changed = cursor.rowcount > 0
    conn.close()
    
    return changed

def soft_delete_user(user_id: int) -> bool:
    """Мягкое удаление пользователя"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
    conn.commit()
    changed = cursor.rowcount > 0
    conn.close()
    
    return changed

def get_all_users() -> List[Dict[str, Any]]:
    """Получает всех пользователей (для админа)"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, email, name, role, is_active, created_at FROM users")
    rows = cursor.fetchall()
    
    conn.close()
    return [dict(row) for row in rows]

# ========== Токены ==========

def save_token(token: str, user_id: int, expires_at: str):
    """Сохраняет токен в БД"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO user_tokens (token, user_id, expires_at)
        VALUES (?, ?, ?)
    """, (token, user_id, expires_at))
    
    conn.commit()
    conn.close()

def get_token(token: str) -> Optional[Dict[str, Any]]:
    """Проверяет существование токена в БД"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM user_tokens WHERE token = ?", (token,))
    row = cursor.fetchone()
    
    conn.close()
    return dict(row) if row else None

def delete_token(token: str):
    """Удаляет токен (при logout)"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM user_tokens WHERE token = ?", (token,))
    conn.commit()
    conn.close()

def delete_user_tokens(user_id: int):
    """Удаляет все токены пользователя"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM user_tokens WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()