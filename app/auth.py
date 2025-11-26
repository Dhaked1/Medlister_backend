from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import hashlib
import secrets
from app.models import SignupRequest, LoginRequest
from app.firebase_client import users_ref

router = APIRouter()

def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with salt"""
    # Generate a random salt
    salt = secrets.token_hex(16)
    # Combine salt and password, then hash
    password_hash = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    # Return salt and hash combined (salt:hash format)
    return f"{salt}:{password_hash}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        # Split salt and hash
        salt, stored_hash = hashed_password.split(":", 1)
        # Hash the plain password with the same salt
        password_hash = hashlib.sha256((salt + plain_password).encode('utf-8')).hexdigest()
        # Compare hashes
        return password_hash == stored_hash
    except ValueError:
        return False

# -----------------------------
# User Signup
# -----------------------------
@router.post("/signup")
def signup(user_data: SignupRequest):
    """
    Register a new user.
    Takes name, email, and password, hashes the password, and saves to database.
    """
    # Check if user already exists
    all_users = users_ref.get()
    if all_users:
        for user_id, user_info in all_users.items():
            if user_info.get("email") == user_data.email:
                raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password
    hashed_password = hash_password(user_data.password)
    
    # Create user data (using email as key for easy lookup)
    user_id = user_data.email.replace(".", "_").replace("@", "_")
    user_data_dict = {
        "name": user_data.name,
        "email": user_data.email,
        "password": hashed_password
    }
    
    # Save to Firebase
    users_ref.child(user_id).set(user_data_dict)
    
    return JSONResponse(
        content={
            "message": "User registered successfully",
            "user": {
                "name": user_data.name,
                "email": user_data.email
            }
        },
        status_code=201
    )

# -----------------------------
# User Login
# -----------------------------
@router.post("/login")
def login(credentials: LoginRequest):
    """
    Authenticate a user.
    Takes email and password, verifies credentials, and returns success status.
    """
    # Find user by email
    all_users = users_ref.get()
    if not all_users:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    user_found = None
    user_id = None
    
    for uid, user_info in all_users.items():
        if user_info.get("email") == credentials.email:
            user_found = user_info
            user_id = uid
            break
    
    if not user_found:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    stored_password = user_found.get("password")
    if not stored_password or not verify_password(credentials.password, stored_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Return success response
    return JSONResponse(
        content={
            "message": "Login successful",
            "status": "ok",
            "user": {
                "name": user_found.get("name"),
                "email": user_found.get("email")
            }
        },
        status_code=200
    )

