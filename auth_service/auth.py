from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import Depends, HTTPException
from bson import ObjectId
import os
from database import users_collection
from dotenv import load_dotenv


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Контекст для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Хэширование пароля

    Args:
        password (str): _description_

    Returns:
        str: _description_
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля

    Args:
        plain_password (str): _description_
        hashed_password (str): _description_

    Returns:
        bool: _description_
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Создание JWT токена

    Args:
        data (dict): _description_
        expires_delta (timedelta | None, optional): _description_. Defaults to None.

    Returns:
        _type_: _description_
    """
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(lambda: "")):
    """Получение текущего пользователя через токен

    Args:
        token (_type_, optional): _description_. Defaults to Depends(lambda: "").

    Raises:
        credentials_exception: _description_
        credentials_exception: _description_
        credentials_exception: _description_

    Returns:
        _type_: _description_
    """
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if user is None:
            raise credentials_exception
        return {"id": str(user["_id"]), "email": user["email"]}
    except JWTError:
        raise credentials_exception
