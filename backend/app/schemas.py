from pydantic import BaseModel, EmailStr
from typing import Optional



# Base de Usuario


class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "operario"


# Crear usuario

class UserCreate(UserBase):
    password: str


# Usuario en respuesta

class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True


# Login

class LoginRequest(BaseModel):
    username: str
    password: str

# Token JWT

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
