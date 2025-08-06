import random
import string
from datetime import datetime, timedelta
from app.core.config import OTP_EXPIRE_MINUTES
from app.db.redis import get_redis
from app.core.security import encrypt_data, decrypt_data
from fastapi import HTTPException, status

# OTP Configuration
OTP_LENGTH = 6
MAX_OTP_ATTEMPTS = 3
MAX_RESEND_ATTEMPTS = 3
RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds
MAX_REQUESTS_PER_WINDOW = 5
MAX_VERIFICATION_ATTEMPTS_PER_WINDOW = 10

def generate_otp() -> str:
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=OTP_LENGTH))

async def check_rate_limit(email: str, action: str) -> bool:
    """Check if user has exceeded rate limits"""
    redis_client = get_redis()
    key = f"rate_limit:{action}:{email}"
    
    try:
        current_count = await redis_client.get(key)
        if current_count and int(current_count) >= MAX_REQUESTS_PER_WINDOW:
            return False
        
        # Increment counter
        await redis_client.incr(key)
        await redis_client.expire(key, RATE_LIMIT_WINDOW)
        return True
    except Exception as e:
        print(f"Rate limit check error: {e}")
        return True  # Allow if Redis fails

async def check_verification_rate_limit(email: str) -> bool:
    """Check verification attempt rate limits"""
    redis_client = get_redis()
    key = f"verification_limit:{email}"
    
    try:
        current_count = await redis_client.get(key)
        if current_count and int(current_count) >= MAX_VERIFICATION_ATTEMPTS_PER_WINDOW:
            return False
        
        # Increment counter
        await redis_client.incr(key)
        await redis_client.expire(key, RATE_LIMIT_WINDOW)
        return True
    except Exception as e:
        print(f"Verification rate limit check error: {e}")
        return True

async def get_existing_otp(email: str) -> dict:
    """Get existing OTP record for email"""
    redis_client = get_redis()
    key = f"otp:{email}"
    
    try:
        otp_data = await redis_client.get(key)
        if otp_data:
            return {
                "exists": True,
                "data": decrypt_data(otp_data)
            }
        return {"exists": False}
    except Exception as e:
        print(f"Error getting existing OTP: {e}")
        return {"exists": False}

async def check_resend_attempts(email: str) -> bool:
    """Check if user can resend OTP"""
    redis_client = get_redis()
    key = f"resend_attempts:{email}"
    
    try:
        attempts = await redis_client.get(key)
        if attempts and int(attempts) >= MAX_RESEND_ATTEMPTS:
            return False
        return True
    except Exception as e:
        print(f"Error checking resend attempts: {e}")
        return True

async def increment_resend_attempts(email: str):
    """Increment resend attempt counter"""
    redis_client = get_redis()
    key = f"resend_attempts:{email}"
    
    try:
        await redis_client.incr(key)
        await redis_client.expire(key, RATE_LIMIT_WINDOW)
    except Exception as e:
        print(f"Error incrementing resend attempts: {e}")

async def store_otp(email: str, otp: str) -> bool:
    """Store OTP in Redis with comprehensive metadata"""
    try:
        redis_client = get_redis()
        key = f"otp:{email}"
        
        # Create OTP record with metadata
        otp_record = {
            "code": otp,
            "email": email,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(minutes=OTP_EXPIRE_MINUTES)).isoformat(),
            "attempts": 0,
            "is_used": False
        }
        
        encrypted_data = encrypt_data(str(otp_record))
        await redis_client.setex(key, OTP_EXPIRE_MINUTES * 60, encrypted_data)
        return True
    except Exception as e:
        print(f"Error storing OTP: {e}")
        return False

async def verify_otp(email: str, otp: str) -> dict:
    """Verify OTP with attempt control and rate limiting"""
    redis_client = get_redis()
    key = f"otp:{email}"
    
    try:
        # Check verification rate limit
        if not await check_verification_rate_limit(email):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many verification attempts. Try again in {RATE_LIMIT_WINDOW // 60} minutes."
            )
        
        # Get OTP record
        otp_data = await redis_client.get(key)
        if not otp_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP not found or expired. Please request a new OTP."
            )
        
        # Decrypt and parse OTP record
        otp_record_str = decrypt_data(otp_data)
        # Convert string back to dict (simplified for demo)
        otp_record = eval(otp_record_str)  # In production, use proper JSON parsing
        
        # Check if OTP is already used
        if otp_record.get("is_used", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP has already been used."
            )
        
        # Check expiry
        expires_at = datetime.fromisoformat(otp_record["expires_at"])
        if datetime.now() > expires_at:
            await redis_client.delete(key)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP has expired. Please request a new OTP."
            )
        
        # Check attempt count
        attempts = otp_record.get("attempts", 0)
        if attempts >= MAX_OTP_ATTEMPTS:
            await redis_client.delete(key)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum OTP attempts exceeded. Please request a new OTP."
            )
        
        # Verify OTP code
        if otp_record["code"] == otp:
            # Mark OTP as used
            otp_record["is_used"] = True
            encrypted_data = encrypt_data(str(otp_record))
            await redis_client.setex(key, OTP_EXPIRE_MINUTES * 60, encrypted_data)
            
            # Clear rate limit counters
            await redis_client.delete(f"rate_limit:otp_request:{email}")
            await redis_client.delete(f"verification_limit:{email}")
            await redis_client.delete(f"resend_attempts:{email}")
            
            return {"success": True, "message": "OTP verified successfully"}
        else:
            # Increment attempt counter
            otp_record["attempts"] = attempts + 1
            encrypted_data = encrypt_data(str(otp_record))
            await redis_client.setex(key, OTP_EXPIRE_MINUTES * 60, encrypted_data)
            
            remaining_attempts = MAX_OTP_ATTEMPTS - otp_record["attempts"]
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Incorrect OTP. {remaining_attempts} attempts remaining."
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error verifying OTP. Please try again."
        )

async def request_otp(email: str) -> dict:
    """Request OTP with comprehensive validation and throttling"""
    try:
        # Check rate limit for OTP requests
        if not await check_rate_limit(email, "otp_request"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many OTP requests. Try again in {RATE_LIMIT_WINDOW // 60} minutes."
            )
        
        # Validate email format (basic validation)
        if "@" not in email or "." not in email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email address format."
            )
        
        # Check existing OTP
        existing_otp = await get_existing_otp(email)
        
        if existing_otp["exists"]:
            # Check resend attempts
            if not await check_resend_attempts(email):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Maximum resend attempts reached. Try again later."
                )
            
            # Increment resend counter
            await increment_resend_attempts(email)
            
            # Resend existing OTP
            await send_otp_email(email, existing_otp["data"]["code"])
            return {
                "success": True,
                "message": "OTP resent successfully",
                "type": "resend"
            }
        else:
            # Generate new OTP
            otp = generate_otp()
            if await store_otp(email, otp):
                await send_otp_email(email, otp)
                return {
                    "success": True,
                    "message": "OTP sent successfully",
                    "type": "new"
                }
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate OTP. Please try again."
                )
                
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error requesting OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing OTP request. Please try again."
        )

async def send_otp_email(email: str, otp: str) -> bool:
    """Send OTP via email (placeholder for now)"""
    # TODO: Implement actual email sending
    print(f"📧 OTP {otp} sent to {email}")
    return True

async def cleanup_expired_otps():
    """Background cleanup process for expired OTPs"""
    # This would be implemented as a background task
    # For now, Redis handles expiration automatically
    pass


