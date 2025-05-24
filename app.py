from flask import Flask, render_template, request, jsonify, session, send_file
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
import os
import base64
import json
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
socketio = SocketIO(app, cors_allowed_origins="*")

# Tạo thư mục upload nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Lưu trữ thông tin phòng và người dùng
rooms_data = {}
users_data = {}

class RSACrypto:
    """Lớp xử lý mã hóa/giải mã RSA và ký số"""
    
    @staticmethod
    def generate_key_pair():
        """Tạo cặp khóa RSA (khóa riêng và khóa công khai)"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Chuyển đổi khóa thành format PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode(), public_pem.decode()
    
    @staticmethod
    def encrypt_text(text, public_key_pem):
        """Mã hóa văn bản bằng khóa công khai RSA"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            
            # RSA chỉ có thể mã hóa dữ liệu nhỏ, nên ta sử dụng AES để mã hóa dữ liệu chính
            # và RSA để mã hóa khóa AES
            aes_key = secrets.token_bytes(32)  # 256-bit key
            iv = secrets.token_bytes(16)  # 128-bit IV
            
            # Mã hóa dữ liệu bằng AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Padding dữ liệu để phù hợp với block size của AES
            padded_data = text.encode()
            padding_length = 16 - (len(padded_data) % 16)
            padded_data += bytes([padding_length] * padding_length)
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Mã hóa khóa AES bằng RSA
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Kết hợp khóa AES đã mã hóa, IV và dữ liệu đã mã hóa
            result = {
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
                'iv': base64.b64encode(iv).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode()
            }
            
            return base64.b64encode(json.dumps(result).encode()).decode()
            
        except Exception as e:
            raise Exception(f"Lỗi mã hóa: {str(e)}")
    
    @staticmethod
    def decrypt_text(encrypted_data, private_key_pem):
        """Giải mã văn bản bằng khóa riêng RSA"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            
            # Giải mã dữ liệu từ base64
            encrypted_json = json.loads(base64.b64decode(encrypted_data).decode())
            
            encrypted_aes_key = base64.b64decode(encrypted_json['encrypted_key'])
            iv = base64.b64decode(encrypted_json['iv'])
            cipher_data = base64.b64decode(encrypted_json['encrypted_data'])
            
            # Giải mã khóa AES bằng RSA
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Giải mã dữ liệu bằng AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(cipher_data) + decryptor.finalize()
            
            # Loại bỏ padding
            padding_length = decrypted_padded[-1]
            decrypted_data = decrypted_padded[:-padding_length]
            
            return decrypted_data.decode()
            
        except Exception as e:
            raise Exception(f"Lỗi giải mã: {str(e)}")
    
    @staticmethod
    def sign_data(data, private_key_pem):
        """Ký số dữ liệu bằng khóa riêng"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            
            signature = private_key.sign(
                data.encode() if isinstance(data, str) else data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            raise Exception(f"Lỗi ký số: {str(e)}")
    
    @staticmethod
    def verify_signature(data, signature, public_key_pem):
        """Xác minh chữ ký số bằng khóa công khai"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            
            signature_bytes = base64.b64decode(signature)
            
            public_key.verify(
                signature_bytes,
                data.encode() if isinstance(data, str) else data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception:
            return False

class RoomManager:
    """Quản lý phòng và người dùng"""
    
    @staticmethod
    def create_room(room_id, creator_id):
        """Tạo phòng mới"""
        if room_id not in rooms_data:
            rooms_data[room_id] = {
                'creator': creator_id,
                'members': {},
                'messages': [],
                'files': [],
                'created_at': datetime.now().isoformat()
            }
            return True
        return False
    
    @staticmethod
    def join_room(room_id, user_id, username, public_key):
        """Tham gia phòng"""
        if room_id not in rooms_data:
            RoomManager.create_room(room_id, user_id)
        
        rooms_data[room_id]['members'][user_id] = {
            'username': username,
            'public_key': public_key,
            'joined_at': datetime.now().isoformat()
        }
        
        return True
    
    @staticmethod
    def leave_room(room_id, user_id):
        """Rời khỏi phòng"""
        if room_id in rooms_data and user_id in rooms_data[room_id]['members']:
            del rooms_data[room_id]['members'][user_id]
            
            # Xóa phòng nếu không còn ai
            if not rooms_data[room_id]['members']:
                del rooms_data[room_id]
            
            return True
        return False
    
    @staticmethod
    def get_room_members(room_id):
        """Lấy danh sách thành viên trong phòng"""
        if room_id in rooms_data:
            return rooms_data[room_id]['members']
        return {}
    
    @staticmethod
    def add_message(room_id, user_id, message_type, content):
        """Thêm tin nhắn vào phòng"""
        if room_id in rooms_data:
            message = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'username': rooms_data[room_id]['members'].get(user_id, {}).get('username', 'Unknown'),
                'type': message_type,
                'content': content,
                'timestamp': datetime.now().isoformat()
            }
            rooms_data[room_id]['messages'].append(message)
            return message
        return None

@app.route('/')
def index():
    """Trang chủ"""
    return render_template('index.html')

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """API tạo cặp khóa RSA"""
    try:
        private_key, public_key = RSACrypto.generate_key_pair()
        return jsonify({
            'success': True,
            'private_key': private_key,
            'public_key': public_key
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt_text():
    """API mã hóa văn bản"""
    try:
        data = request.get_json()
        text = data.get('text')
        public_key = data.get('public_key')
        
        if not text or not public_key:
            return jsonify({
                'success': False,
                'error': 'Thiếu văn bản hoặc khóa công khai'
            }), 400
        
        encrypted = RSACrypto.encrypt_text(text, public_key)
        return jsonify({
            'success': True,
            'encrypted_text': encrypted
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_text():
    """API giải mã văn bản"""
    try:
        data = request.get_json()
        encrypted_text = data.get('encrypted_text')
        private_key = data.get('private_key')
        
        if not encrypted_text or not private_key:
            return jsonify({
                'success': False,
                'error': 'Thiếu văn bản mã hóa hoặc khóa riêng'
            }), 400
        
        decrypted = RSACrypto.decrypt_text(encrypted_text, private_key)
        return jsonify({
            'success': True,
            'decrypted_text': decrypted
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/sign', methods=['POST'])
def sign_text():
    """API ký số văn bản"""
    try:
        data = request.get_json()
        text = data.get('text')
        private_key = data.get('private_key')
        
        if not text or not private_key:
            return jsonify({
                'success': False,
                'error': 'Thiếu văn bản hoặc khóa riêng'
            }), 400
        
        signature = RSACrypto.sign_data(text, private_key)
        return jsonify({
            'success': True,
            'signature': signature
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/verify', methods=['POST'])
def verify_signature():
    """API xác minh chữ ký số"""
    try:
        data = request.get_json()
        text = data.get('text')
        signature = data.get('signature')
        public_key = data.get('public_key')
        
        if not text or not signature or not public_key:
            return jsonify({
                'success': False,
                'error': 'Thiếu thông tin xác minh'
            }), 400
        
        is_valid = RSACrypto.verify_signature(text, signature, public_key)
        return jsonify({
            'success': True,
            'is_valid': is_valid
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Socket Events
@socketio.on('join')
def on_join(data):
    """Xử lý khi người dùng tham gia phòng"""
    try:
        room_id = data['room']
        username = data['username']
        public_key = data['public_key']
        user_id = str(uuid.uuid4())
        
        # Lưu thông tin người dùng
        users_data[request.sid] = {
            'user_id': user_id,
            'username': username,
            'room': room_id,
            'public_key': public_key
        }
        
        # Tham gia phòng
        join_room(room_id)
        RoomManager.join_room(room_id, user_id, username, public_key)
        
        # Thông báo cho tất cả trong phòng
        emit('user_joined', {
            'username': username,
            'user_id': user_id,
            'members': RoomManager.get_room_members(room_id)
        }, room=room_id)
        
        # Gửi lịch sử tin nhắn cho người mới tham gia
        if room_id in rooms_data:
            emit('message_history', {
                'messages': rooms_data[room_id]['messages']
            })
        
    except Exception as e:
        emit('error', {'message': f'Lỗi tham gia phòng: {str(e)}'})

@socketio.on('leave')
def on_leave():
    """Xử lý khi người dùng rời phòng"""
    try:
        if request.sid in users_data:
            user_data = users_data[request.sid]
            room_id = user_data['room']
            user_id = user_data['user_id']
            username = user_data['username']
            
            leave_room(room_id)
            RoomManager.leave_room(room_id, user_id)
            
            # Thông báo cho tất cả trong phòng
            emit('user_left', {
                'username': username,
                'user_id': user_id,
                'members': RoomManager.get_room_members(room_id)
            }, room=room_id)
            
            del users_data[request.sid]
            
    except Exception as e:
        emit('error', {'message': f'Lỗi rời phòng: {str(e)}'})

@socketio.on('send_message')
def handle_message(data):
    """Xử lý gửi tin nhắn"""
    try:
        if request.sid not in users_data:
            emit('error', {'message': 'Bạn chưa tham gia phòng'})
            return
        
        user_data = users_data[request.sid]
        room_id = user_data['room']
        user_id = user_data['user_id']
        
        message = RoomManager.add_message(
            room_id, 
            user_id, 
            data['type'], 
            data['content']
        )
        
        if message:
            emit('new_message', message, room=room_id)
        
    except Exception as e:
        emit('error', {'message': f'Lỗi gửi tin nhắn: {str(e)}'})

@socketio.on('send_file')
def handle_send_file(data):
    """Xử lý gửi file mã hóa"""
    try:
        if request.sid not in users_data:
            emit('error', {'message': 'Bạn chưa tham gia phòng'})
            return

        user_data = users_data[request.sid]
        room_id = user_data['room']
        user_id = user_data['user_id']

        # Lấy thông tin file từ dữ liệu gửi lên
        file_content = base64.b64decode(data['file_content'])
        filename = data['filename']
        public_key = data['public_key']

        # Mã hóa file bằng AES và RSA
        aes_key = secrets.token_bytes(32)  # 256-bit key
        iv = secrets.token_bytes(16)  # 128-bit IV

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding dữ liệu để phù hợp với block size của AES
        padding_length = 16 - (len(file_content) % 16)
        file_content += bytes([padding_length] * padding_length)

        encrypted_file = encryptor.update(file_content) + encryptor.finalize()

        # Mã hóa khóa AES bằng RSA
        public_key_obj = serialization.load_pem_public_key(public_key.encode(), backend=default_backend())
        encrypted_aes_key = public_key_obj.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Gửi file mã hóa và thông tin giải mã đến phòng
        emit('new_file', {
            'filename': filename,
            'encrypted_file': base64.b64encode(encrypted_file).decode(),
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
            'iv': base64.b64encode(iv).decode(),
            'sender': user_data['username']
        }, room=room_id)

    except Exception as e:
        emit('error', {'message': f'Lỗi gửi file: {str(e)}'})

@socketio.on('disconnect')
def handle_disconnect():
    """Xử lý khi người dùng ngắt kết nối"""
    if request.sid in users_data:
        on_leave()

if __name__ == '__main__':
    print("🚀 Khởi động ứng dụng mã hóa RSA...")
    print("📝 Truy cập: http://localhost:5000")
    print("🔐 Các chức năng:")
    print("   - Tạo cặp khóa RSA")
    print("   - Mã hóa/Giải mã văn bản")
    print("   - Ký số và xác minh")
    print("   - Phòng chat thời gian thực")
    print("   - Truyền file mã hóa")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)