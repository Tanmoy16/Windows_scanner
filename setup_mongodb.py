"""
Local MongoDB Setup Helper
===========================

Prerequisites:
1. Install MongoDB Community Server from https://www.mongodb.com/try/download/community
2. Ensure the 'mongod' service is running (default port 27017)

Then run this script to test the connection:
    python setup_mongodb.py
"""

from pymongo import MongoClient

# Local MongoDB connection string
MONGO_URI = "mongodb://localhost:27017/winscan_db"

def test_connection():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        # The ping command will fail if cannot connect
        client.admin.command('ping')
        print("✓ MongoDB connection successful!")
        
        # Create collections if they don't exist
        db = client.winscan_db
        if 'users' not in db.list_collection_names():
            db.create_collection('users')
            print("✓ Created 'users' collection")
        
        if 'reports' not in db.list_collection_names():
            db.create_collection('reports')
            print("✓ Created 'reports' collection")
            
        print("\nLocal MongoDB is ready to use!")
        return True
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        print("\nPlease make sure MongoDB is installed and the 'mongod' service is running.")
        print("Download: https://www.mongodb.com/try/download/community")
        return False

if __name__ == "__main__":
    print("Testing local MongoDB connection...\n")
    test_connection()
