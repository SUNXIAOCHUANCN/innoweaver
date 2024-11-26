from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from routes import *
from utils.tasks import *
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
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
