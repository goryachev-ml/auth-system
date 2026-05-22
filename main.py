"""
main.py - веб-сервер на FastAPI
Собственная система аутентификации и авторизации
"""

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Optional

from database import (
    create_tables, create_user, get_user_by_email, get_user_by_id,
    update_user, soft_delete_user, get_all_users,
    save_token, get_token, delete_token, delete_user_tokens
)

SECRET_KEY = "my-super-secret-key-change-me-12345"
ALGORITHM = "HS256"
TOKEN_EXPIRE_DAYS = 7

# Включаем безопасность для Swagger (появится замочек)
security = HTTPBearer()

app = FastAPI(
    title="Своя система аутентификации", 
    redoc_url=None,
    swagger_ui_parameters={
        "defaultModelsExpandDepth": -1,  # убираем Schemas
    }
)

create_tables()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def create_token(user_id: int) -> str:
    expires_at = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
    payload = {"user_id": user_id, "exp": expires_at}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    save_token(token, user_id, expires_at.isoformat())
    return token

def get_current_user_from_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        
        if not get_token(token):
            return None
        
        user = get_user_by_id(user_id)
        if user and user.get("is_active"):
            return user
        return None
    except:
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Получает текущего пользователя из токена (для Swagger)"""
    token = credentials.credentials
    user = get_current_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Неверный или просроченный токен")
    return user

def get_current_user_optional(request: Request) -> Optional[dict]:
    """Получает пользователя из заголовка (для middleware)"""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    
    return get_current_user_from_token(parts[1])

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    request.state.user = get_current_user_optional(request)
    return await call_next(request)

# ========== АУТЕНТИФИКАЦИЯ ==========

@app.post("/auth/register")
def register(email: str, name: str, password: str, password_confirm: str, role: str = "user"):
    if password != password_confirm:
        raise HTTPException(status_code=400, detail="Пароли не совпадают")
    if len(password) < 3:
        raise HTTPException(status_code=400, detail="Пароль слишком короткий")
    if role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Роль должна быть 'user' или 'admin'")
    
    if get_user_by_email(email):
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    
    user_id = create_user(email, name, hash_password(password), role)
    token = create_token(user_id)
    
    return {"message": "Регистрация успешна", "user_id": user_id, "role": role, "token": token}

@app.post("/auth/login")
def login(email: str, password: str):
    user = get_user_by_email(email)
    
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=401, detail="Неверный email или пароль")
    
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Неверный email или пароль")
    
    token = create_token(user["id"])
    
    return {
        "message": "Вход выполнен", 
        "user_id": user["id"], 
        "name": user["name"], 
        "role": user["role"], 
        "token": token
    }

@app.post("/auth/logout")
def logout(current_user: dict = Depends(get_current_user), request: Request = None):
    """Требует авторизации (появится замочек)"""
    auth_header = request.headers.get("Authorization")
    token = auth_header.split()[1] if auth_header else None
    if token:
        delete_token(token)
    return {"message": "Выход выполнен"}

@app.get("/auth/me")
def get_my_profile(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"], 
        "email": current_user["email"], 
        "name": current_user["name"], 
        "role": current_user["role"], 
        "is_active": current_user["is_active"]
    }

@app.put("/auth/me")
def update_my_profile(name: str = None, current_user: dict = Depends(get_current_user)):
    if name:
        update_user(current_user["id"], name=name)
    return {"message": "Профиль обновлен"}

@app.delete("/auth/me")
def delete_my_account(current_user: dict = Depends(get_current_user)):
    delete_user_tokens(current_user["id"])
    soft_delete_user(current_user["id"])
    return {"message": "Аккаунт удален"}

# ========== АДМИНКА ==========

@app.get("/admin/users")
def admin_get_users(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещен. Требуется роль admin")
    
    return {"users": get_all_users()}

@app.put("/admin/users/{user_id}/role")
def admin_set_role(user_id: int, role: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    if role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Роль должна быть 'user' или 'admin'")
    if not get_user_by_id(user_id):
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    update_user(user_id, role=role)
    return {"message": f"Роль пользователя {user_id} изменена на {role}"}

# ========== РЕСУРС ==========

@app.get("/resource")
def get_resource(current_user: dict = Depends(get_current_user)):
    role = current_user.get("role")
    return {
        "message": f"Доступ разрешен ({'администратор' if role == 'admin' else 'пользователь'})",
        "data": "Секретные данные" if role == "admin" else "Обычные данные"
    }

if __name__ == "__main__":
    print("=" * 50)
    print("Сервер запущен, нажмите: http://127.0.0.1:8000/docs")
    print("ИНСТРУКЦИЯ:")
    print("1. Нажмите Register, 'Try it out', Execute для ролей admin и прочих")
    print("2. Нажмите Login, 'Try it out', Execute и скопируйте полученый токен (Ctrl+c):")
    print("3. Нажмите на кнопку 'Authorize' (замочек открыт в правом верхнем углу)")
    print("4. Втавьте полученный при логине токен и нажмите Authorize, Close")
    print("5. Протестируйте аутентификацию и авторизацию по всем остальным разноцветным кнопкам ('Try it out', Execute)")
    print("=" * 50)
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)