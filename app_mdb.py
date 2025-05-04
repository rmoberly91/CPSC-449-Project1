from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import jwt, JWTError
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
from bson import ObjectId
import os

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

# Helpers
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
    name: str
    description: str = ""
    quantity: int
    price: float

class InventoryOut(InventoryBase):
    id: str
    owner_id: str

# Routes
@app.post("/register")
async def register(user: UserCreate):
    existing = await users_collection.find_one({"$or": [{"username": user.username}, {"email": user.email}]})
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    user_doc = {
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "is_admin": False
    }
    await users_collection.insert_one(user_doc)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await users_collection.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/inventory")
async def create_inventory(item: InventoryBase, user: dict = Depends(get_current_user)):
    item_doc = item.dict()
    item_doc["owner_id"] = str(user["_id"])
    result = await inventory_collection.insert_one(item_doc)
    item_doc["id"] = str(result.inserted_id)
    return {"message": "Item added successfully", "item": item_doc}

@app.get("/inventory", response_model=list[InventoryOut])
async def get_inventory(user: dict = Depends(get_current_user)):
    cursor = inventory_collection.find({"owner_id": str(user["_id"])})
    items = []
    async for item in cursor:
        item["id"] = str(item["_id"])
        items.append(InventoryOut(**item))
    return items

@app.get("/inventory/{item_id}", response_model=InventoryOut)
async def get_inventory_item(item_id: str, user: dict = Depends(get_current_user)):
    item = await inventory_collection.find_one({"_id": ObjectId(item_id), "owner_id": str(user["_id"])})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item["id"] = str(item["_id"])
    return InventoryOut(**item)

@app.put("/inventory/{item_id}")
async def update_inventory(item_id: str, update: InventoryBase, user: dict = Depends(get_current_user)):
    result = await inventory_collection.update_one(
        {"_id": ObjectId(item_id), "owner_id": str(user["_id"])},
        {"$set": update.dict()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item updated successfully"}

@app.delete("/inventory/{item_id}")
async def delete_inventory(item_id: str, user: dict = Depends(get_current_user)):
    result = await inventory_collection.delete_one({"_id": ObjectId(item_id), "owner_id": str(user["_id"])})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted successfully"}
