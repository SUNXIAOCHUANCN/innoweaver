from pymongo import MongoClient
import bcrypt
from bson.objectid import ObjectId
from meilisearch import Client
import base64

def update_user_to_meilisearch(user):
    if user:
        user['_id'] = str(user['_id'])
        user['password'] = base64.b64encode(user['password']).decode('utf-8')
        meili_client = Client('http://127.0.0.1:7700')
        index = meili_client.index('user_id')
        index.add_documents([user])
        
# 连接 MongoDB
client = MongoClient('mongodb://localhost:27017/')

# 选择或创建 user_management_db 数据库
db = client['userDB']
users_collection = db['users']

# 密码加密函数
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# 插入“0号用户”
zero_user = {
    "_id": ObjectId(),  # 生成唯一的用户 ID
    "name": "CHI2025",
    "email": "CHI2025",
    "password": hash_password("Inlab2024!"),  # 加密后的密码
    "user_type": "developer",
}

# 插入用户到 users 集合
insert_result = users_collection.insert_one(zero_user)
print(insert_result)

result = users_collection.find_one(                
                {'_id': ObjectId(zero_user['_id'])},
        )
update_user_to_meilisearch(result)

# 输出结果
if insert_result.acknowledged:
    print(f"成功插入用户，用户 ID: {result.inserted_id}")
else:
    print("插入用户失败")