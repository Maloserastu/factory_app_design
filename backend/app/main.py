from fastapi import FastAPI
from .database import Base, engine
from .routers import auth

from fastapi.middleware.cors import CORSMiddleware




app = FastAPI()

origins = [
    "http://localhost:5173",  # puerto donde corre tu frontend
]

app.add_middleware(  #middleware permite la conexion entre el front y el end, ahora ya se puede hacer fetch
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# Crear tablas al arrancar
Base.metadata.create_all(bind=engine)

# Registrar rutas
app.include_router(auth.router)

@app.get("/")
def root():
    return {"status": "ok", "message": "Backend funcionando"}
