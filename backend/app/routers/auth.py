from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm


from ..database import get_db
from ..models import User
from ..schemas import UserCreate, LoginRequest, UserResponse, TokenResponse


# Configuración JWT Y HASHING


SECRET_KEY = "SUPER_SECRET_KEY"   # provisional, habría que cambiarlo para una app en producción
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")  # define como se extrae el token
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  # configuración de Passlib para usar bcrypt

router = APIRouter(  # Hacer que funcione como un router en FastAPI
    prefix="/auth",
    tags=["Auth"]
)


# UTILIDADES DE AUTENTICACIÓN


def hash_password(password: str):  # devuelve el hash (bcrypt)
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str):  # comprueba si el hash guardado coincide con el hash guardado en la BD
    return pwd_context.verify(password, hashed)

def create_access_token(data: dict):  # crea un JWT usando el diccionario Data con la secret_key.
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


# Se obtiene el usuario desde el JWT


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # se extrae del token JWT el sub-> nombre y el role
        username = payload.get("sub")
        role = payload.get("role")
        # Si falta alguno de los datos o el token está modificado o tiene algún error
        if username is None or role is None:
            raise HTTPException(401, "Token inválido")

    except JWTError:
        raise HTTPException(401, "Token inválido")

    # se busca si el usuario existe o no en la base de datos
    user = db.query(User).filter(User.username == username).first()

    if not user:
        raise HTTPException(401, "Usuario no encontrado")

    return user



# Restricción por rol


def require_role(required_role: str):
    def wrapper(current_user=Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=403,
                detail=f"No tienes el rol requerido: {required_role}"
            )
        return current_user
    return wrapper



# ENDPOINT: register  // Creado para el backend, para asi poder crear usuarios de prueba y demas


@router.post("/register", response_model=UserResponse)
def register(  # se reciben datos y se abre sesión de db
    payload: UserCreate,  # ahora se usa un schema que contiene username, email, password, role
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),  
    # Protege register para que los usuarios solo puedan ser creados por otros usuarios admin

):
    if payload.role not in ["admin", "operario", "manager"]:
        raise HTTPException(400, "Rol no válido")

    # Comprueba que no exista un usuario con ese nombre o email y salta un error si ya existe
    exists = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()

    if exists:
        raise HTTPException(400, "Usuario o email ya existe")

    print("PASSWORD RECIBIDA:", repr(payload.password), type(payload.password))

    # Crea el user y lo añade a la bd con una contraseña hasheada
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user  # gracias al response_model no devuelve la contraseña hash



# ENDPOINT: login


@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(User.username == form_data.username).first()
    # se comprueba si el usuario existe y si la contraseña coincide con el hash en BD

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(401, "Credenciales incorrectas")

    # genera el JWT con el nombre y el role.
    token = create_access_token({
        "sub": user.username,
        "role": user.role
    })

    # devuelve token y rol (schema se encarga del formato)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role
    )



# endpoint para el current_user


@router.get("/me", response_model=UserResponse)  # devuelve info del usuario logeado sin exponer la contraseña
def me(user=Depends(get_current_user)):
    return user



# endpoints por rol


@router.get("/admin-only")
def admin_only(user=Depends(require_role("admin"))):
    return {"msg": f"Hola admin {user.username}"}

@router.get("/manager-only")
def manager_only(user=Depends(require_role("manager"))):
    return {"msg": f"Hola manager {user.username}"}

@router.get("/operario-only")
def operario_only(user=Depends(require_role("operario"))):
    return {"msg": f"Hola operario {user.username}"}
