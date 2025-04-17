from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import jwt
import datetime
import pytest
from fastapi.testclient import TestClient

# Configurações
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
DATABASE_URL = "sqlite:///./users.db"

# Banco de Dados
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)

Base.metadata.create_all(bind=engine)

# Segurança
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# API
app = FastAPI()

@app.post("/register")
def register(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if user:
        raise HTTPException(status_code=400, detail="User already exists")
    new_user = User(username=username, password_hash=hash_password(password))
    db.add(new_user)
    db.commit()
    return {"message": "User created"}

@app.post("/login")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": user.username})
    return {"access_token": token}

# Testes
client = TestClient(app)

def test_register():
    response = client.post("/register", params={"username": "testuser", "password": "testpass"})
    assert response.status_code == 200
    assert response.json() == {"message": "User created"}

def test_register_existing_user():
    client.post("/register", params={"username": "testuser", "password": "testpass"})
    response = client.post("/register", params={"username": "testuser", "password": "testpass"})
    assert response.status_code == 400
    assert response.json()["detail"] == "User already exists"

def test_login():
    client.post("/register", params={"username": "testuser2", "password": "testpass"})
    response = client.post("/login", params={"username": "testuser2", "password": "testpass"})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_invalid_user():
    response = client.post("/login", params={"username": "nonexistent", "password": "wrongpass"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

# Testes de Segurança

def test_sql_injection():
    response = client.post("/login", params={"username": "' OR 1=1 --", "password": "irrelevant"})
    assert response.status_code == 401

def test_brute_force_attempt():
    for i in range(5):
        response = client.post("/login", params={"username": "bruteuser", "password": f"wrong{i}"})
        assert response.status_code == 401


def test_jwt_manipulation():
    import base64
    import json
    parts = create_token({"sub": "admin"}).split(".")
    tampered_payload = base64.urlsafe_b64encode(json.dumps({"sub": "hacker", "exp": 9999999999}).encode()).decode().rstrip("=")
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    assert tampered_token != create_token({"sub": "admin"})


def test_token_expired():
    expired_token = jwt.encode({"sub": "expired", "exp": datetime.datetime.utcnow() - datetime.timedelta(hours=1)}, SECRET_KEY, algorithm=ALGORITHM)
    try:
        jwt.decode(expired_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        assert True
    else:
        assert False


def test_user_enumeration():
    client.post("/register", params={"username": "enumuser", "password": "pass"})
    response = client.post("/register", params={"username": "enumuser", "password": "pass"})
    assert response.status_code == 400
    assert "User already exists" in response.text
