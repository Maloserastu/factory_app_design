from fastapi import FastAPI
from .database import Base, engine
from .routers import auth

app = FastAPI()

# Crear tablas al arrancar
Base.metadata.create_all(bind=engine)

# Registrar rutas
app.include_router(auth.router)

@app.get("/")
def root():
    return {"status": "ok", "message": "Backend funcionando"}
