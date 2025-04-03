import sqlite3
import uuid
import datetime
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send, join_room, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,   #HTTPS 환경이면 True
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=30)
)
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="서버 오류가 발생했습니다."), 500

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                role TEXT DEFAULT 'user',
                status TEXT DEFAULT 'active',
                failed_attempts INTEGER DEFAULT 0,
                last_failed_login TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                bank_name TEXT,
                account_number TEXT,
                account_holder TEXT,
                visibility TEXT DEFAULT 'visible'
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
        """)
        ###관리자 로그 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_log (
                id TEXT PRIMARY KEY,
                admin_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        db.commit()

#관리자 활동 로그 기록
def log_admin_action(admin_id, action, target_type, target_id):
    db = get_db()
    cursor = db.cursor()
    log_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO admin_log (id, admin_id, action, target_type, target_id, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (log_id, admin_id, action, target_type, target_id, timestamp))
    db.commit()

# #테스트용 에러 페이지
# @app.route('/crash')
# def crash():
#     raise Exception("테스트용 내부 오류 발생!") #Exception
# @app.route('/dberror')
# def db_error():
#     db = get_db()
#     cursor = db.cursor()
#     cursor.execute("SELECT * FROM not_a_real_table")  # 존재하지 않는 테이블
#     return "실행됨"
# @app.route('/typeerror')
# def type_error():
#     return 5 + "문자열"  # 타입 불일치

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        # 사용자명 유효성 검사 (영문, 숫자, 밑줄만 허용, 4~20자)
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
            flash("아이디 형식이 올바르지 않습니다.")
            return redirect(url_for('register'))
        # 비밀번호 최소 길이 검사
        if len(password) < 8:
            flash("비밀번호는 8자 이상이어야 합니다.")
            return redirect(url_for('register'))
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

#로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        # 사용자명 유효성 검사 (영문, 숫자, 밑줄만 허용, 4~20자)
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
            flash("아이디 형식이 올바르지 않습니다.")
            return redirect(url_for('login'))
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            MAX_ATTEMPTS = 5
            LOCK_TIME = 60  # seconds

            if user['failed_attempts'] >= MAX_ATTEMPTS and user['last_failed_login']:
                last_fail = datetime.datetime.strptime(user['last_failed_login'], '%Y-%m-%d %H:%M:%S')
                delta = datetime.datetime.now() - last_fail
                if delta.total_seconds() < LOCK_TIME:
                    flash("로그인 시도 횟수를 초과했습니다. 잠시 후 다시 시도해주세요.")
                    return redirect(url_for('login'))

            if user['password'] == password:
                if user['status'] == 'suspended':
                    flash('정지된 계정입니다. 관리자에게 문의하세요.')
                    return redirect(url_for('login'))
                session['user_id'] = user['id']
                session.permanent = True
                cursor.execute("UPDATE user SET failed_attempts = 0, last_failed_login = NULL WHERE id = ?", (user['id'],))
                db.commit()
                flash('로그인 성공!')
                return redirect(url_for('dashboard'))
            else:
                now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("UPDATE user SET failed_attempts = failed_attempts + 1, last_failed_login = ? WHERE id = ?", (now, user['id']))
                db.commit()
                flash('아이디 또는 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('login'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 정보
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 검색어와 정렬 기준
    query = request.args.get('q', '').strip()
    sort = request.args.get('sort', 'newest')
    sql = "SELECT * FROM product WHERE visibility = 'visible'"
    params = []
    if len(query) >= 1:
        sql += " AND title LIKE ?"
        params.append(f"%{query}%")
    if sort == 'price':
        sql += " ORDER BY CAST(price AS INTEGER) ASC"
    else:  # 기본값 = 최신순
        sql += " ORDER BY rowid DESC"
    cursor.execute(sql, params)
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 관리자 페이지: 관리자 기능 수행(유저 정지/상품 숨김/신고 처리 등)
@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    if not current_user or current_user['role'] != 'admin':
        abort(403)
    # 사용자 목록
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    # 유저 ID → 이름 맵
    user_map = {u['id']: u['username'] for u in users}
    # 상품 목록
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    # 신고 목록
    cursor.execute("SELECT * FROM report")
    reports = cursor.fetchall()
    # 신고자 이름 붙이기
    report_dicts = []
    for r in reports:
        r = dict(r)
        r['reporter_name'] = user_map.get(r['reporter_id'], r['reporter_id'][:8])
        r['target_name'] = user_map.get(r['target_id'], r['target_id'][:8])  # optional
        report_dicts.append(r)
    # 관리자 활동 로그
    cursor.execute("SELECT * FROM admin_log ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    # Row 객체를 dict로 바꾸고 이름 붙이기
    log_dicts = []
    for log in logs:
        log = dict(log)
        log['admin_name'] = user_map.get(log['admin_id'], log['admin_id'][:8])
        if log['target_type'] == 'user':
            log['target_name'] = user_map.get(log['target_id'], log['target_id'][:8])
        else:
            log['target_name'] = log['target_id'][:8]
        log_dicts.append(log)
    return render_template('admin.html', users=users, products=products, reports=report_dicts, user=current_user, logs=log_dicts)

#관리자 페이지: 사용자 정지
@app.route('/admin/toggle_user/<user_id>')
def toggle_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 관리자 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin_user = cursor.fetchone()
    if not admin_user or admin_user['role'] != 'admin':
        abort(403)
    # 현재 상태 확인
    cursor.execute("SELECT status FROM user WHERE id = ?", (user_id,))
    target_user = cursor.fetchone()
    if target_user:
        new_status = 'active' if target_user['status'] == 'suspended' else 'suspended'
        cursor.execute("UPDATE user SET status = ? WHERE id = ?", (new_status, user_id))
        db.commit()
        log_admin_action(admin_user['id'], f'user_{new_status}', 'user', user_id)
    return redirect(url_for('admin'))

#관리자 페이지: 상품 숨기기
@app.route('/admin/toggle_product/<product_id>')
def toggle_product_visibility(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 관리자 인증
    cursor.execute("SELECT id, role FROM user WHERE id = ?", (session['user_id'],))
    admin_user = cursor.fetchone()
    if not admin_user or admin_user['role'] != 'admin':
        abort(403)
    cursor.execute("SELECT visibility FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if product:
        new_visibility = 'visible' if product['visibility'] == 'hidden' else 'hidden'
        cursor.execute("UPDATE product SET visibility = ? WHERE id = ?", (new_visibility, product_id))
        db.commit()
        log_admin_action(admin_user['id'], f'product_{new_visibility}', 'product', product_id)
    return redirect(url_for('admin'))

# 관리자 페이지: 상품 삭제
@app.route('/admin/delete_product/<product_id>')
def admin_delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 관리자 인증
    cursor.execute("SELECT id, role FROM user WHERE id = ?", (session['user_id'],))
    admin_user = cursor.fetchone()
    if not admin_user or admin_user['role'] != 'admin':
        abort(403)
    # 상품 존재 확인
    cursor.execute("SELECT id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('admin'))
    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    # 관리자 로그 기록
    log_admin_action(admin_user['id'], 'product_deleted', 'product', product_id)
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('admin'))

#관리자 페이지: 신고 처리하기
@app.route('/admin/update_report/<report_id>')
def update_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    admin_user = cursor.fetchone()
    if not admin_user or admin_user['role'] != 'admin':
        abort(403)

    cursor.execute("SELECT status FROM report WHERE id = ?", (report_id,))
    report = cursor.fetchone()
    if report:
        current = report['status']
        if current == 'pending':
            new_status = 'in_progress'
        elif current == 'in_progress':
            cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
            new_status = 'resolved'
        else:
            new_status = 'pending'
        cursor.execute("UPDATE report SET status = ? WHERE id = ?", (new_status, report_id))
        db.commit()
        log_admin_action(admin_user['id'], f'report_{new_status}', 'report', report_id)
    return redirect(url_for('admin'))

# 프로필 페이지: bio 업데이트 가능, 올린 상품 목록 확인
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 정보
    cursor.execute("SELECT id, username, bio FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 소개글 업데이트
    if request.method == 'POST':
        bio = request.form['bio']
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash("프로필이 업데이트되었습니다.")
        return redirect(url_for('profile'))
    # 내가 등록한 상품 목록
    cursor.execute("SELECT id, title, price FROM product WHERE seller_id = ?", (session['user_id'],))
    my_products = cursor.fetchall()
    return render_template('profile.html', user=current_user, products=my_products)


# 프로필 페이지: 비밀번호 업데이트 기능
@app.route('/update_password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_pw = request.form['current_password']
    new_pw = request.form['new_password']

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 비밀번호 확인
    cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if not user:
        flash("사용자를 찾을 수 없습니다.")
        return redirect(url_for('profile'))

    if user['password'] != current_pw:
        flash("현재 비밀번호가 일치하지 않습니다.")
        return redirect(url_for('profile'))

    # 새 비밀번호로 업데이트
    cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_pw, session['user_id']))
    db.commit()

    flash("비밀번호가 성공적으로 변경되었습니다.")
    return redirect(url_for('profile'))

# 내가 올린 상품 수정
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 가져오기
    cursor.execute("SELECT id, title, description, price, seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 상품이 없거나 남의 상품일 경우
    if not product or product['seller_id'] != session['user_id']:
        flash("수정 권한이 없습니다.")
        return redirect(url_for('profile'))

    if request.method == 'POST':
        new_title = request.form['title']
        new_desc = request.form['description']
        new_price = request.form['price']

        cursor.execute("""
            UPDATE product 
            SET title = ?, description = ?, price = ? 
            WHERE id = ?
        """, (new_title, new_desc, new_price, product_id))
        db.commit()

        flash("상품이 수정되었습니다.")
        return redirect(url_for('profile'))

    return render_template('edit_product.html', product=product)

# 내가 올린 상품 삭제
@app.route('/product/delete/<product_id>')
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 확인
    cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('profile'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()

    flash("상품이 삭제되었습니다.")
    return redirect(url_for('profile'))

# 사용자 검색 기능
@app.route('/search_user')
def search_user():
    username = request.args.get('username')
    if not username:
        flash('Username is required.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, bio FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        return redirect(url_for('view_user', username=username))
    else:
        flash('User not found.')
        return redirect(url_for('dashboard'))

# 대시보드:  사용자 프로필 조회
@app.route('/user/<username>')
def view_user(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, bio FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        flash('User not found.')
        return redirect(url_for('dashboard'))

    return render_template('view_user.html', user=user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        bank_name = request.form['bank_name']
        account_number = request.form['account_number']
        account_holder = request.form['account_holder']

        try:
            price = int(request.form['price'])  #문자열 정수로 변환
        except ValueError:
            flash('가격은 숫자만 입력해주세요.')
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, bank_name, account_number, account_holder) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'], bank_name, account_number, account_holder)
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ? AND visibility = 'visible'", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

#송금 정보 보기
@app.route('/payment_info/<product_id>')
def payment_info(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT bank_name, account_number, account_holder FROM product WHERE id = ?", (product_id,))
    info = cursor.fetchone()
    if info is None:
        return "해당 상품이 존재하지 않습니다.", 404
    return render_template('payment_info.html', info=info)


# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 실시간 채팅: 1대1 채팅
@app.route('/chat/<username>')
def private_chat(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자
    cursor.execute("SELECT id, username FROM user WHERE id = ?", (session['user_id'],))
    me = cursor.fetchone()

    # 상대방 정보 조회
    cursor.execute("SELECT id, username FROM user WHERE username = ?", (username,))
    target = cursor.fetchone()

    if not target or target['id'] == me['id']:
        flash("잘못된 사용자입니다.")
        return redirect(url_for('dashboard'))

    # 메시지 조회 없음 → 휘발성 채팅이므로
    return render_template('chat.html', me=me, target=target, messages=[])

# 방 참여
@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)
    print(f"[입장] {room} 입장 완료")

# 메시지 송수신 (휘발성)
@socketio.on('private_message')
def handle_private_message(data):
    room = data['room']
    sender_name = data['sender_name']
    message = data['message']

    print(f"[chat] {sender_name}: {message}")
    emit('private_message', {
        'sender_name': sender_name,
        'message': message
    }, to=room)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True) #배포 시 False로 변경, 우선은 True로 설정해두자.
