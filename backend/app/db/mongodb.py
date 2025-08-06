from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
from app.core.config import MONGO_URL, DATABASE_NAME

class Database:
    client: AsyncIOMotorClient = None
    db = None

db = Database()

async def connect_to_mongo():
    """Create database connection"""
    try:
        db.client = AsyncIOMotorClient(MONGO_URL, server_api=ServerApi('1'))
        db.db = db.client[DATABASE_NAME]
        
        # Test the connection
        await db.client.admin.command('ping')
        print("✅ Successfully connected to MongoDB Atlas!")
    except Exception as e:
        print(f"⚠️  MongoDB connection failed: {e}")
        print("⚠️  App will start but database features won't work")
        db.client = None
        db.db = None

async def close_mongo_connection():
    """Close database connection"""
    if db.client:
        db.client.close()
        print("Disconnected from MongoDB")

def get_database():
    """Get database instance"""
    return db.db