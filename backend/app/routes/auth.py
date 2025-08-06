from fastapi import APIRouter, HTTPException, Depends, status
from app.schemas.user import UserCreate, UserLogin, OTPVerify, UserResponse, TokenResponse, MessageResponse
from app.core.security import hash_password, verify_password, create_access_token, encrypt_data
from app.utils.otp import request_otp, verify_otp
from app.db.mongodb import get_database
from app.db.redis import get_redis
from datetime import datetime
from bson import ObjectId

router = APIRouter()

@router.post("/register", response_model=MessageResponse)
async def register(user_data: UserCreate):
    """Register a new user and send OTP"""
    db = get_database()
    
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    existing_username = await db.users.find_one({"username": user_data.username})
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Create user document
    user_doc = {
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "role": "viewer",  # Default role
        "is_verified": False,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
    
    # Insert user
    result = await db.users.insert_one(user_doc)
    
    # Request OTP with enhanced validation
    otp_result = await request_otp(user_data.email)
    
    return MessageResponse(message=f"Registration successful. {otp_result['message']}")

@router.post("/verify-otp", response_model=TokenResponse)
async def verify_registration_otp(otp_data: OTPVerify):
    """Verify OTP and activate user account"""
    db = get_database()
    
    # Verify OTP with enhanced validation
    verify_result = await verify_otp(otp_data.email, otp_data.otp)
    if not verify_result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=verify_result["message"]
        )
    
    # Update user verification status
    user = await db.users.find_one_and_update(
        {"email": otp_data.email},
        {"$set": {"is_verified": True, "updated_at": datetime.now()}},
        return_document=True
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Create access token
    token_data = {"sub": str(user["_id"]), "email": user["email"], "role": user["role"]}
    access_token = create_access_token(token_data)
    
    # Create user response
    user_response = UserResponse(
        id=str(user["_id"]),
        username=user["username"],
        email=user["email"],
        role=user["role"],
        is_verified=user["is_verified"],
        created_at=user["created_at"]
    )
    
    return TokenResponse(access_token=access_token, user=user_response)

@router.post("/request-otp", response_model=MessageResponse)
async def request_otp_endpoint(email: str):
    """Request OTP for email verification"""
    try:
        result = await request_otp(email)
        return MessageResponse(message=result["message"])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to request OTP. Please try again."
        )

@router.post("/login", response_model=MessageResponse)
async def login(user_data: UserLogin):
    """Login and send OTP for verification"""
    db = get_database()
    
    # Find user
    user = await db.users.find_one({"email": user_data.email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    if not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Check if user is verified
    if not user["is_verified"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please verify your email first through registration"
        )
    
    # Request OTP with enhanced validation
    otp_result = await request_otp(user_data.email)
    
    return MessageResponse(message=f"Login OTP sent to your email. {otp_result['message']}")

@router.post("/verify-login", response_model=TokenResponse)
async def verify_login_otp(otp_data: OTPVerify):
    """Verify login OTP and issue access token"""
    db = get_database()
    
    # Verify OTP with enhanced validation
    verify_result = await verify_otp(otp_data.email, otp_data.otp)
    if not verify_result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=verify_result["message"]
        )
    
    # Get user
    user = await db.users.find_one({"email": otp_data.email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Create access token
    token_data = {"sub": str(user["_id"]), "email": user["email"], "role": user["role"]}
    access_token = create_access_token(token_data)
    
    # Create user response
    user_response = UserResponse(
        id=str(user["_id"]),
        username=user["username"],
        email=user["email"],
        role=user["role"],
        is_verified=user["is_verified"],
        created_at=user["created_at"]
    )
    
    return TokenResponse(access_token=access_token, user=user_response) 