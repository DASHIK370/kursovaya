from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
import hashlib
import hmac
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///schedule.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(stored_hash: str, password: str) -> bool:
    return hmac.compare_digest(stored_hash, hash_password(password))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password: str):
        self.password_hash = hash_password(password)

    def check_password(self, password: str) -> bool:
        return verify_password(self.password_hash, password)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    lessons = db.relationship('Lesson', backref='group', lazy=True)


class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    week = db.Column(db.Integer, nullable=False)
    weekday = db.Column(db.Integer, nullable=False)
    lesson_number = db.Column(db.Integer, nullable=False)

    subject = db.Column(db.String(128), nullable=False)

    lesson_type = db.Column(db.String(20), nullable=False)

    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    teacher_name = db.Column(db.String(128), nullable=False)
    classroom_name = db.Column(db.String(64), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return wrapped


with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    groups = Group.query.order_by(Group.name).all()
    return render_template('index.html', groups=groups)


@app.route('/group/<int:group_id>')
def group_schedule(group_id):
    group = Group.query.get_or_404(group_id)

    week = request.args.get('week', type=int) or 1
    week = max(1, min(25, week))

    lessons = Lesson.query.filter_by(group_id=group.id, week=week).all()

    return render_template('group_schedule.html',
                           group=group,
                           lessons=lessons,
                           current_week=week)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not username or not email or not password:
            flash('Все поля обязательны.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Такой пользователь уже существует.', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна, войдите в систему.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Вы вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
@admin_required
def admin_index():
    groups = Group.query.order_by(Group.name).all()
    lessons = Lesson.query.order_by(Lesson.week, Lesson.weekday, Lesson.lesson_number).all()
    return render_template('admin/index.html',
                           groups=groups,
                           lessons=lessons)

@app.route('/admin/groups/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_group():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash('Название группы обязательно.', 'danger')
            return redirect(url_for('admin_add_group'))
        if Group.query.filter_by(name=name).first():
            flash('Такая группа уже есть.', 'danger')
            return redirect(url_for('admin_add_group'))
        g = Group(name=name)
        db.session.add(g)
        db.session.commit()
        flash('Группа добавлена.', 'success')
        return redirect(url_for('admin_index'))
    return render_template('admin/add_group.html')


@app.route('/admin/lessons/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_lesson():
    groups = Group.query.order_by(Group.name).all()

    if request.method == 'POST':
        group_id = int(request.form['group_id'])
        week = int(request.form['week'])
        lesson_type = request.form['lesson_type']

        teacher_name = request.form['teacher_name'].strip()
        classroom_name = request.form['classroom_name'].strip()
        subject = request.form['subject'].strip()
        weekday = int(request.form['weekday'])
        lesson_number = int(request.form['lesson_number'])

        if not (teacher_name and classroom_name and subject):
            flash('Все текстовые поля обязательны.', 'danger')
            return redirect(url_for('admin_add_lesson'))

        lesson = Lesson(
            week=week,
            weekday=weekday,
            lesson_number=lesson_number,
            subject=subject,
            lesson_type=lesson_type,
            group_id=group_id,
            teacher_name=teacher_name,
            classroom_name=classroom_name
        )
        db.session.add(lesson)
        db.session.commit()
        flash('Занятие добавлено.', 'success')
        return redirect(url_for('admin_index'))

    return render_template('admin/add_lesson.html', groups=groups)


@app.route('/admin/lessons/<int:lesson_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    db.session.delete(lesson)
    db.session.commit()
    flash('Занятие удалено.', 'info')
    return redirect(url_for('admin_index'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
