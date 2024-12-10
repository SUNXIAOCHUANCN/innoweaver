from flask import Blueprint, app, request, jsonify
from flask_cors import CORS
from routes import *
from utils.tasks import *

import utils.tasks as USER
from utils.auth_utils import token_required, validate_input
from utils.redis import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager,  create_access_token, create_refresh_token,jwt_required,get_jwt_identity
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from utils.tasks.config import *
import jwt
import bcrypt
import uuid

limiter = Limiter(
    app,
    key_func=get_remote_address,  # 使用客户端的IP地址作为速率限制的依据，区分不同的请求来源
    default_limits=["100 per minute"]  # 设置默认的速率限制，每分钟最多100次请求（可根据实际情况调整）
)


auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/api/register', methods=['POST'])
@validate_input(['email', 'name', 'password', 'user_type'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.json
        email = data.get('email')
        name = data.get('name')
        password = data.get('password')
        user_type = data.get('user_type')

        response, status_code = USER.register_user(email, name, password, user_type)
        print(response)
        return jsonify(response), status_code

     # 生成带有有效期的激活令牌，这里设置有效期为24小时（以秒为单位，86400秒）

    except KeyError as e:
        return jsonify({"error": f"Missing key: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An error occurred during registration", "details": str(e)}), 500
    
     # 生成带有有效期的激活令牌，这里设置有效期为24小时（以秒为单位，86400秒）
    token = serializer.dumps({'user_id': new_user.user_id}, salt='activation_token', expires_in=86400)
    activation_link = f"{request.url_root}api/activate/{new_user.user_id}/{token}"

    try:
        # 发送包含认证链接的邮件
        # 发送包含认证链接的邮件，这里假设mail对象已经在Flask应用中配置好并关联过来了
        msg = Mail.Message('账户激活', recipients=[email])
        msg.body = f"请点击以下链接激活您的账户：{activation_link}，链接有效期为24小时。"
        mail.send(msg)
        return jsonify({"message": "注册成功，请前往邮箱完成账户激活"}), 201
    except:
        # 如果邮件发送失败，可根据实际情况进行处理，比如回滚数据库操作等，这里简单返回错误信息
        return jsonify({"error": "邮件发送失败，请稍后重试或联系客服"}), 500
    
@auth_bp.route('/api/activate/<string:user_id>/<string:token>', methods=['GET'])
def activate(user_id, token):
    try:
        # 验证令牌是否有效以及对应的用户ID是否匹配
        data = serializer.loads(token, salt='activation_token', max_age=86400)
        if data.get('user_id') == user_id:
            # 根据用户ID激活用户账户
            result = users_collection.update_one(
                {'user_id': user_id},
                {'$set': {'is_active': True}}
            )
            if result.modified_count == 1:
                return jsonify({"message": "账户已成功激活，您可以登录使用了"}), 200
        return jsonify({"error": "无效的激活链接，请检查链接是否正确或重新申请激活"}), 400
    except:
        return jsonify({"error": "激活链接已过期或无效，请重新申请激活"}), 400

@auth_bp.route('/api/resend_activation_email', methods=['POST'])
def resend_activation_email():
    data = request.json
    email = data.get('email')

    # 查找对应邮箱的未激活用户
    user = users_collection.find_one({'email': email, 'is_active': False})
    if not user:
        return jsonify({"error": "未找到对应的未激活用户，请检查邮箱是否正确"}), 400

    # 重新生成带有有效期的激活令牌
    token = serializer.dumps({'user_id': user['user_id']}, salt='activation_token', expires_in=86400)
    activation_link = f"{request.url_root}api/activate/{user['user_id']}/{token}"

    try:
        # 发送包含新认证链接的邮件
        msg = Mail.Message('账户激活', recipients=[email])
        msg.body = f"这是重新发送的激活链接，请点击以下链接激活您的账户：{activation_link}，链接有效期为24小时。"
        mail.send(msg)
        return jsonify({"message": "激活邮件已重新发送，请查看邮箱"}), 200
    except:
        return jsonify({"error": "邮件发送失败，请稍后重试或联系客服"}), 500

@auth_bp.route('/api/login', methods=['POST'])
@validate_input(['email', 'password'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        cache_key = f"login_attempts:{email}"
        attempts = redis_client.get(cache_key)
        if attempts and int(attempts) >= 10:
            return jsonify({"error": "Too many login attempts, please try again later."}), 429

        response, status_code = USER.login_user(email, password)
        if status_code == 200:

            user_id = response.get('user_id')

            # 生成访问令牌，携带用户身份信息（这里简单示例为用户ID，实际可根据需要包含更多信息）
            access_token = create_access_token(identity=user_id)
            # 生成刷新令牌
            refresh_token = create_refresh_token(identity=user_id)
             # 缓存会话信息，现在包含访问令牌和刷新令牌等关键信息，可根据实际情况调整缓存的数据结构和内容
            session_data = {
                "user_id": user_id,
                "access_token": access_token,
                "refresh_token": refresh_token
            }
            redis_client.setex(f"user_session:{user_id}", 3600, json.dumps(response))  # 缓存会话1小时

            # 登录成功后重置尝试次数
            redis_client.delete(cache_key)

            return jsonify({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "message": "Login successful"
            }), 200
        else:
            # 登录失败，增加登录尝试次数
            redis_client.incr(cache_key)
            redis_client.expire(cache_key, 300)
            
        return jsonify(response), status_code
    
    except KeyError as e:
        return jsonify({"error": f"Missing key: {str(e)}"}), 400
    except Exception as e:
        print(f"exc: {str(e)}")
        return jsonify({"error": "An error occurred during login", "details": str(e)}), 500

@auth_bp.route('/api/get_user', methods=['POST'])
@token_required
@jwt_required()
def get_user(current_user):
    try:
        return jsonify(current_user), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while retrieving the user", "details": str(e)}), 500

@auth_bp.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)  # 要求请求携带有效刷新令牌
def refresh():
    try:
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        return jsonify({
            "access_token": new_access_token,
            "message": "Access token refreshed successfully"
        }), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while refreshing the access token", "details": str(e)}), 500
    
