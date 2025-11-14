from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

DATABASE_URL = os.getenv("DATABASE_URL")

# Engine para PostgreSQL, es la conexión principal
engine = create_engine(
    DATABASE_URL, # type: ignore
    pool_pre_ping=True  # mejora la seguridad haciendo un ping a la conexión para asegurarse de que sige viva
)

# Creación de una sesión
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Clase base para modelos
Base = declarative_base()


# Se encarga de abrir una sesión con la base de datos en cuestión y cerrarla al terminar.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
