from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from .. import models, schemas, auth
from ..database import get_db

router = APIRouter(prefix="/users", tags=["Users"])

# CRUD Endpoints
# Get current user profile
@router.get("/profile", response_model=schemas.UserResponse)
def get_profile(current_user: models.User = Depends(auth.get_current_active_user)):
    return current_user

# Verify token endpoint
@router.post("/verify-token")
def verify_token_endpoint(current_user: models.User = Depends(auth.get_current_active_user)):
    return {"message": "Token válido", "user": current_user.email}

# get all users
@router.get("/users/", response_model=List[schemas.UserResponse])
def get_users(current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return users

# get user by id
@router.get("/users/{user_id}", response_model=schemas.UserResponse)
def get_user(user_id: int, current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    return user

# create new user
@router.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email ya registrado")
    
    new_user = models.User(
        name=user.name, 
        email=user.email, 
        role=user.role,
        hashed_pwd=auth.    get_password_hash(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# update user by id
@router.put("/users/{user_id}", response_model=schemas.UserResponse)
def update_user(user_id: int, user_update: schemas.UserUpdate, current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    update_data = user_update.model_dump(exclude_unset=True)
    if "password" in update_data:
        update_data["hashed_pwd"] = auth.get_password_hash(update_data.pop("password"))
    
    for key, value in update_data.items():
        setattr(db_user, key, value)

    db.commit()
    db.refresh(db_user)
    return db_user

# delete user by id
@router.delete("/users/{user_id}")
def delete_user(user_id: int, current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    if db_user.id == current_user.id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario")
    
    db.delete(db_user)
    db.commit()
    return {"message": "Usuario eliminado exitosamente"}

