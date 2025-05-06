from fastapi import FastAPI, HTTPException, Depends, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from fastapi_sessions.frontends.implementations import SessionCookie, CookieParameters
from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier
from uuid import uuid4, UUID
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import os
import re
import logging

app = FastAPI()
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.ERROR)

# DB config
MYSQL_URL = os.getenv("MYSQL_URL", "mysql+pymysql://user:password@localhost/inventory_db")
engine = create_engine(MYSQL_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Auth config
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session config
# SET TO EXPIRE IN 30 MINUTES
SESSION_EXPIRE_MINUTES = 2
cookie_params = CookieParameters(max_age=SESSION_EXPIRE_MINUTES * 60)  # Cookie expires with session
SESSION_SECRET = os.getenv("SESSION_SECFRET", "your_session_secret")
session_cookie = SessionCookie(
    cookie_name="session_cookie",
    identifier="general_verifier",
    auto_error=True,
    secret_key=SESSION_SECRET,
    cookie_params=cookie_params,
)
backend = InMemoryBackend[UUID, dict]()

class BasicVerifier(SessionVerifier[UUID, dict]):
    async def verify_session(self, model: dict) -> bool:
        return True  

async def get_session_data(session_id: Optional[UUID] = Depends(session_cookie)):
    if session_id is None:
        raise HTTPException(status_code=401, detail="No session")
    session_data = await backend.read(session_id)
    if session_data is None:
        raise HTTPException(status_code=401, detail="Invalid session")
    # Check expiration
    if session_data.expires_at < datetime.utcnow():
        await backend.delete(session_id)
        raise HTTPException(status_code=401, detail="Session expired")
    return session_data

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
    serves = Column(Integer, nullable=False)
    calories = Column(Integer, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="items")

Base.metadata.create_all(bind=engine)

# Schemas
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    is_admin: bool = False  

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
    id: int
    owner_id: int

class SessionData(BaseModel):
    user_id: int
    username: str
    expires_at: datetime

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
    price_regex = r'^[0-9]+\.[0-9]{2}$'
    return re.match(price_regex, f"{price:.2f}")

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

# Admin-only dependency
def admin_required(user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# Routes
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="User already exists")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    if not validate_email(user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    password_error = validate_password(user.password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)
    hashed_pw = hash_password(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        password=hashed_pw,
        is_admin=user.is_admin
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), 
                db: Session = Depends(get_db)):
    user = get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username})

    # Set session cookie using Pydantic model
    session_id = uuid4()
    expires_at = datetime.utcnow() + timedelta(minutes=SESSION_EXPIRE_MINUTES)
    session_data = SessionData(
        user_id=user.id,
        username=user.username,
        expires_at=expires_at
    )
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
def create_inventory(item: InventoryBase, db: Session = Depends(get_db), user: User = Depends(get_current_user), session_data: dict = Depends(get_session_data)):
    if db.query(Inventory).filter(Inventory.name == item.name).first():
        raise HTTPException(status_code=400, detail="Item already exists")
    if not isinstance(item.name, str):
        raise HTTPException(status_code=400, detail="Name must be a string")
    if not isinstance(item.description, str):
        raise HTTPException(status_code=400, detail="Description must be a string")
    if not isinstance(item.quantity, int) or item.quantity < 0:
        raise HTTPException(status_code=400, detail="Quantity must be a non-negative integer")
    if not isinstance(item.price, float) or not validate_price(item.price) or item.price < 0:
        raise HTTPException(status_code=400, detail="Price must be a float in a valid US format greater than $0.00")
    new_item = Inventory(**item.dict(), owner_id=user.id)
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return {"message": "Item added successfully", "item": new_item}

@app.get("/inventory", response_model=list[InventoryOut])
def get_inventory(db: Session = Depends(get_db), user: User = Depends(get_current_user),
                  session_data: dict = Depends(get_session_data)):
    items = db.query(Inventory).filter(Inventory.owner_id == user.id).all()
    return items

@app.get("/inventory/{item_id}", response_model=InventoryOut)
def get_inventory_item(item_id: int, db: Session = Depends(get_db),
                       user: User = Depends(get_current_user), session_data: dict = Depends(get_session_data)):
    item = db.query(Inventory).filter(Inventory.id == item_id, Inventory.owner_id == user.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

@app.put("/inventory/{item_id}")
def update_inventory(item_id: int, update: InventoryBase, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user), session_data: dict = Depends(get_session_data)):
    item = db.query(Inventory).filter(Inventory.id == item_id, Inventory.owner_id == user.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    for key, value in update.dict().items():
        setattr(item, key, value)
    db.commit()
    return {"message": "Item updated successfully"}

@app.delete("/inventory/{item_id}")
def delete_inventory(item_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user), 
                     session_data: dict = Depends(get_session_data)):
    item = db.query(Inventory).filter(Inventory.id == item_id, Inventory.owner_id == user.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(item)
    db.commit()
    return {"message": "Item deleted successfully"}

@app.delete("/admin/inventory/{item_id}")
def delete_any_inventory_item(item_id: int, db: Session = Depends(get_db), admin_user: User = Depends(admin_required)):
    item = db.query(Inventory).filter(Inventory.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(item)
    db.commit()
    return {"message": f"Item '{item.name}' (ID {item_id}) deleted by admin."}


@app.exception_handler(Exception) # Global exception handler
async def global_exception_handler(request: Request, exc: Exception): 
    if isinstance(exc, RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "error": "Validation Error",
                "details": exc.errors(),
                "body": exc.body,
            },
        )
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail},
        )
    if isinstance(exc, IntegrityError):
        logger.error(f"Integrity error on {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"error": "Database integrity error", "detail": str(exc.orig)},
        )
    if isinstance(exc, SQLAlchemyError):
        logger.error(f"SQLAlchemy error on {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Database error", "detail": str(exc)},
        )
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error"},
    )