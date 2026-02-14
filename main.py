from fastapi import FastAPI
from app.database import engine, Base
from app.routers import users, login

# Start server with: uvicorn main:app --reload

# Create database tables
Base.metadata.create_all(bind=engine)

# FastAPI Application
app = FastAPI(title="Integracion SQL y FastAPI")

# Include Routers
app.include_router(login.router)
app.include_router(users.router)

# Root Endpoint
@app.get("/")
def root():
    return {"message": "Bienvenido a la API de Integración SQL y FastAPI"}