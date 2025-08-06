import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

# JWT Settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-jwt-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database Settings
MONGO_URL = os.getenv("MONGO_URL")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
DATABASE_NAME = "BlogSite"


FERNET_KEY = os.getenv("FERNET_KEY", Fernet.generate_key().decode())


OTP_EXPIRE_MINUTES = 5

