import sqlite3
import uuid
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
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
                status TEXT DEFAULT 'active'
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
        username = request.form['username']
        password = request.form['password']
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

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            if user['status'] == 'suspended':
                flash('정지된 계정입니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
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

#사용자 정지
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

#상품 숨기기
@app.route('/admin/toggle_product/<product_id>')
def toggle_product_visibility(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 관리자 인증
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
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

#신고 처리하기
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

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

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

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
