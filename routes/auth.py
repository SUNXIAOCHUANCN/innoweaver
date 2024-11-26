from flask import Blueprint, app, request, jsonify
import utils.tasks as USER
from utils.auth_utils import token_required, validate_input
from utils.redis import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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

    except KeyError as e:
        return jsonify({"error": f"Missing key: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An error occurred during registration", "details": str(e)}), 500

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
            token = response.get('token')
            redis_client.setex(f"user_session:{user_id}", 3600, json.dumps(response))  # 缓存会话1小时

            # 登录成功后重置尝试次数
            redis_client.delete(cache_key)
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
def get_user(current_user):
    try:
        return jsonify(current_user), 200
    except Exception as e:
        return jsonify({"error": "An error occurred while retrieving the user", "details": str(e)}), 500
