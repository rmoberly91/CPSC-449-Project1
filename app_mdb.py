from fastapi import FastAPI, HTTPException, Depends, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from fastapi_sessions.frontends.implementations import SessionCookie, CookieParameters
from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier
from uuid import uuid4, UUID
from passlib.context import CryptContext
from jose import jwt, JWTError
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
from bson import ObjectId
from typing import Optional
import os
import re

app = FastAPI()

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URI)
db = client["inventory_db"]
users_collection = db["users"]
inventory_collection = db["inventory"]

# Auth setup
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Session Setup ---
cookie_params = CookieParameters()
SESSION_SECRET = os.getenv("SESSION_SECRET", "your_session_secret")
session_cookie = SessionCookie(
    cookie_name="session_cookie",
    identifier="general_verifier",
    auto_error=True,
    secret_key=SESSION_SECRET,
    cookie_params=cookie_params,
)
backend = InMemoryBackend[UUID, dict]()

class BasicVerifier(SessionVerifier[UUID, dict]):
    def __init__(self, *, identifier: str, backend, auto_error: bool):
        super().__init__(identifier=identifier, auto_error=auto_error)
        self.backend = backend

    async def verify_session(self, model: dict) -> bool:
        return True  # Add custom logic if needed

verifier = BasicVerifier(identifier="general_verifier", backend=backend, auto_error=True)

async def get_session_data(session_id: Optional[UUID] = Depends(session_cookie)):
    if session_id is None:
        raise HTTPException(status_code=401, detail="No session")
    session_data = await backend.read(session_id)
    if session_data is None:
        raise HTTPException(status_code=401, detail="Invalid session")
    return session_data

# Helpers
def validate_email(email: str):
    email_regex = r'^[a-zA-z0-9_.+-]+@[a-zA-Z0-9]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def validate_password(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not re.search(r'\d', password):
        return "Password must contain at least one digit"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'[\W_]', password):
        return "Password must contain at least one special character"
    return None

def validate_price(price: float):
    price_regex = r'^[1-9]+\.[1-9]{2}$'
    return re.match(price_regex, price)

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate token")

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class InventoryBase(BaseModel):
    name: str = Field(..., description="Name of the item")
    description: str = Field("", description="Description of the item")
    quantity: int = Field(..., gt=0, description="Quantity must be greater than 0")
    price: float = Field(..., gt=0, description="Price must be greater than 0")
    serves: int = Field(..., gt=0, description="Serves must be greater than 0")
    calories: int = Field(..., gt=0, description="Calories must be greater than 0")

class InventoryOut(InventoryBase):
    id: str
    owner_id: str

# Routes
@app.post("/register")
async def register(user: UserCreate):
    existing_user = await users_collection.find_one({"$or": [{"username": user.username}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    existing_email = await users_collection.find_one({"$or": [{"email": user.email}]})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    if not validate_email(user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    password_error = validate_password(user.password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)

    user_doc = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "is_admin": False
    }
    await users_collection.insert_one(user_doc)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user = await users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user["username"]})

    # Set session cookie
    session_id = uuid4()
    session_data = {"user_id": str(user["_id"]), "username": user["username"]}
    await backend.create(session_id, session_data)
    session_cookie.attach_to_response(response, session_id)

    return {"access_token": token, "token_type": "bearer"}

@app.post("/logout")
async def logout(response: Response, session_id: Optional[UUID] = Depends(session_cookie)):
    if session_id:
        await backend.delete(session_id)
        session_cookie.delete_from_response(response)
    return {"message": "Logged out"}

@app.post("/inventory")
async def create_inventory(item: InventoryBase, user: dict = Depends(get_current_user), session_data: dict = Depends(get_session_data)):
    existing_item = await inventory_collection.find_one({"$or": [{"name": item.name}]})
    if existing_item:
        raise HTTPException(status_code=400, detail="Item already exists")
    
    if not isinstance(item.name, str):
        raise HTTPException(status_code=400, detail="Name must be a string")
    
    if not isinstance(item.description, str):
        raise HTTPException(status_code=400, detail="Description must be a string")
    
    if not isinstance(item.quantity, int) or item.quantity < 0:
        raise HTTPException(status_code=400, detail="Quantity must be a non-negative integer")
    
    if not isinstance(item.price, float) or not validate_price(item.price) or item.price < 0:
        raise HTTPException(status_code=400, detail="Price must be a float in a valid US format greater than $0.00")
    
    item_doc = item.dict()
    item_doc["owner_id"] = str(user["_id"])
    result = await inventory_collection.insert_one(item_doc)
    item_doc["id"] = str(result.inserted_id)
    return {"message": "Item added successfully", "item": item_doc}

@app.get("/inventory", response_model=list[InventoryOut])
async def get_inventory(user: dict = Depends(get_current_user), session_data: dict = Depends(get_session_data)):
    cursor = inventory_collection.find({"owner_id": str(user["_id"])})
    items = []
    async for item in cursor:
        item["id"] = str(item["_id"])
        items.append(InventoryOut(**item))
    return items

@app.get("/inventory/{item_id}", response_model=InventoryOut)
async def get_inventory_item(item_id: str, user: dict = Depends(get_current_user), 
                             session_data: dict = Depends(get_session_data)):
    item = await inventory_collection.find_one({"_id": ObjectId(item_id), "owner_id": str(user["_id"])})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item["id"] = str(item["_id"])
    return InventoryOut(**item)

@app.put("/inventory/{item_id}")
async def update_inventory(item_id: str, update: InventoryBase, user: dict = Depends(get_current_user),
    session_data: dict = Depends(get_session_data)):
    result = await inventory_collection.update_one(
        {"_id": ObjectId(item_id), "owner_id": str(user["_id"])},
        {"$set": update.dict()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item updated successfully"}

@app.delete("/inventory/{item_id}")
async def delete_inventory(item_id: str, user: dict = Depends(get_current_user),
    session_data: dict = Depends(get_session_data)):
    result = await inventory_collection.delete_one({"_id": ObjectId(item_id), "owner_id": str(user["_id"])})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted successfully"}