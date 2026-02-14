from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt

from . import models, schemas
from .database import get_db

# Security Setup
SECRET_KEY = "your_key"
ALGORITHM = "HS256"
TOKEN_EXPIRES = 30  # minutes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Security Functions
def get_password_hash(password: str) -> str:
    # Bcrypt requiere bytes, así que convertimos la str a bytes
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    # Devolvemos el hash como string para guardarlo en la DB
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_byte_enc = plain_password.encode('utf-8')
    # Si hashed_password viene de la DB como string, hay que pasarlo a bytes
    hashed_password_bytes = hashed_password.encode('utf-8') 
    return bcrypt.checkpw(password_byte_enc, hashed_password_bytes)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
    
def verify_token(token: str) -> Optional[schemas.TokenData]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=401, 
                detail="No se pudo validar el token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = schemas.TokenData(email=email)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401, 
            detail="No se pudo validar el token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data

# Auth Dependencies
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    token_data = verify_token(token)
    user = db.query(models.User).filter(models.User.email == token_data.email).first()
    if user is None:
        raise HTTPException(
            status_code=401, 
            detail="Usuario no existe",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def get_current_active_user(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(
            status_code=401, 
            detail="Usuario inactivo",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user