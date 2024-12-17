from fastapi import APIRouter, HTTPException, Depends
from models import UserCreate, UserLogin, UserResponse, Token
from auth import hash_password, verify_password, create_access_token, get_current_user
from database import users_collection

router = APIRouter()


@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate):
    """Регистрация пользователя

    Args:
        user (UserCreate): _description_

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_
    """
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user.password)
    new_user = {"email": user.email, "hashed_password": hashed_password}
    result = await users_collection.insert_one(new_user)

    return UserResponse(id=str(result.inserted_id), email=user.email)


@router.post("/login", response_model=Token)
async def login(user: UserLogin):
    """Логин пользователя

    Args:
        user (UserLogin): _description_

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_
    """
    db_user = await users_collection.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": str(db_user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """Пример защищенного эндпоинта"""
    return current_user
