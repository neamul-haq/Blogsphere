
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from urllib.parse import quote_plus

# URL-encode the password to handle special characters
password = quote_plus("hlwblog@mongo")
uri = f"mongodb+srv://neamulhaq:{password}@blogsite.slbkmw4.mongodb.net/?retryWrites=true&w=majority&appName=BlogSite"

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)