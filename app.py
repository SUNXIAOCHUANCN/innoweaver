from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from routes import *
from utils.tasks import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token,create_refresh_token,jwt_required, get_jwt_identity

app = Flask(__name__)

# 设置JWT密钥，这是用于对令牌进行签名和验证的关键，要保证其保密性，可替换为复杂的随机字符串
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
# 配置访问令牌的过期时间（以秒为单位，这里设置为30分钟，即1800秒，可根据实际需求调整）
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 1800
# 配置刷新令牌的过期时间（以秒为单位，这里设置为7天，即604800秒，可按需更改）
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 604800

jwt_manager = JWTManager(app)
CORS(app)  # 启用跨域支持

limiter = Limiter(
    app,
    key_func=get_remote_address,  # 使用客户端的IP地址作为速率限制的依据，区分不同的请求来源
    default_limits=["100 per minute"]  # 设置默认的速率限制，每分钟最多100次请求
)

# 注册蓝图
app.register_blueprint(auth_bp)
app.register_blueprint(task_bp)
app.register_blueprint(query_bp)
app.register_blueprint(load_bp)
app.register_blueprint(prompts_bp)

@app.route('/hello', methods=['GET'])
def hello():
    return "Hello World!"

@app.route('/')
def index():
    return render_template('index.html')

#用户登录接口速率限制
@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # 这里是登录逻辑处理代码，比如验证用户名和密码等
    return jsonify({"message": "Login successful"})

# 注册接口速率限制
@auth_bp.route('/api/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    # 注册逻辑处理代码，例如创建新用户账号等
    return jsonify({"message": "Registration successful"})

# 查询接口速率限制
@query_bp.route('/api/query_solution', methods=['GET'])
@limiter.limit("20 per minute")
def query_solution():
    # 查询逻辑处理代码，比如从数据库获取数据等
    return jsonify({"results": []})    

if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5001, debug=True)
    app.run(host='0.0.0.0', port=5000, debug=False)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "You have exceeded the allowed request rate. Please try again later."
    }), 429   
