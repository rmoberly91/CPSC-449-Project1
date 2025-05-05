from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import os
import re

app = FastAPI()

# DB config
MYSQL_URL = os.getenv("MYSQL_URL", "mysql+pymysql://username:password@localhost/inventory_db")
engine = create_engine(MYSQL_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Auth config
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    is_admin = Column(Boolean, default=False)
    items = relationship("Inventory", back_populates="owner")

class Inventory(Base):
    __tablename__ = "inventory"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(200))
    quantity = Column(Integer, nullable=False)
    price = Column(Float, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="items")

Base.metadata.create_all(bind=engine)

# Schemas
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
    id: int
    owner_id: int

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user_by_username(db, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate token")

# Routes
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    # user cannot already exist
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="User already exists")
    
    # email cannot already exist
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # validate email (formatting)
    if not validate_email(user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # validate password (8 characters, uppercase letter(s), lowercase letter(s), number(s), special character(s))
    password_error = validate_password(user.password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)

    hashed_pw = hash_password(user.password)
    new_user = User(username=user.username, email=user.email, password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/inventory")
def create_inventory(item: InventoryBase, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # item cannot already exist
    if db.query(Inventory).filter(Inventory.name == item.name).first():
        raise HTTPException(status_code=400, detail="Item already exists")
    
    # validate item details
    if not isinstance(item.name, str):
        raise HTTPException(status_code=400, detail="Name must be a string")
    if not isinstance(item.description, str):
        raise HTTPException(status_code=400, detail="Description must be a string")
    if not isinstance(item.quantity, int):
        raise HTTPException(status_code=400, detail="Quantity must be an integer")
    if not isinstance(item.price, float) or not validate_price(item.price):
        raise HTTPException(status_code=400, detail="Price must be a float in a valid US format")
    
    new_item = Inventory(**item.dict(), owner_id=user.id)
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return {"message": "Item added successfully", "item": new_item}

@app.get("/inventory", response_model=list[InventoryOut])
def get_inventory(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    items = db.query(Inventory).filter(Inventory.owner_id == user.id).all()
    return items

@app.get("/inventory/{item_id}", response_model=InventoryOut)
def get_inventory_item(item_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.query(Inventory).filter(Inventory.id == item_id, Inventory.owner_id == user.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

@app.put("/inventory/{item_id}")
def update_inventory(item_id: int, update: InventoryBase, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.query(Inventory).filter(Inventory.id == item_id, Inventory.owner_id == user.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    for key, value in update.dict().items():
        setattr(item, key, value)
    db.commit()
    return {"message": "Item updated successfully"}

@app.delete("/inventory/{item_id}")
def delete_inventory(item_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    item = db.query(Inventory).filter(Inventory.id == item_id, Inventory.owner_id == user.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(item)
    db.commit()
    return {"message": "Item deleted successfully"}
