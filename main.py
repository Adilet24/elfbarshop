from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)

db = SQLAlchemy()
bcrypt = Bcrypt()


app = Flask(__name__)

app.secret_key = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# login_manager.init_app(app)
db.init_app(app)
bcrypt.init_app(app)


login_manager = LoginManager(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(300), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    pwd = db.Column(db.String(300), nullable=False)
    roll = db.Column(db.String)

    def __repr__(self):
        return '<User %r>' % self.full_name


class Items(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), unique=True, nullable=False)
    content = db.Column(db.String(300), unique=True, nullable=False)
    price = db.Column(db.String(300), nullable=False, unique=True)
    img = db.Column(db.String)
    category = db.Column(db.String)
    amount = db.Column(db.Integer, nullable=False)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    items = Items.query.all()
    if current_user.is_authenticated:
        return render_template('index.html', title='VapeLid', url='profile', log=current_user.email, items=items)
    return render_template('index.html', title='VapeLid', url='login', log='Login', items=items)


@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    sign = request.form['sign']
    if sign == 'Login':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.pwd, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Email or password are wrong')

    elif sign == 'Sign up':
        register(request.form['email'], request.form['full_name'], request.form['password'], request.form['c_password'])
    else:
        return render_template('error.html',
                               status_code=400,
                               message='Something went wrong'), 400
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


def register(email, full_name, password, c_password):
    if password != c_password:
        flash('passwords are not equal!')
        return
    if (not email.endswith('.com')) and (not email.endswith('.ru')):
        flash('email incorrect')
        return
    if not User.query.filter_by(email=email).first():
        user = User(full_name=full_name, email=email, pwd=bcrypt.generate_password_hash(password), roll='user')
        db.session.add(user)
        db.session.commit()
    else:
        flash('This email are already taken!')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html',
                           log=current_user.email,
                           full_name=current_user.full_name)


@app.route('/update_user', methods=['GET'])
@login_required
def update_user():
    return render_template('update_user.html',
                           log=current_user.email,
                           full_name=current_user.full_name)


@app.route('/update_user', methods=['POST'])
@login_required
def update_user_post():
    email = request.form['email']
    full_name = request.form['full_name']
    data = User.query.filter_by(id=current_user.id).first()
    b = False
    if email != current_user.email:
        data.email = email
        b = True
    if full_name != current_user.full_name:
        data.full_name = full_name
        b = True
    if b:
        db.session.commit()
        logout_user()
        login_user(data)
    return redirect(url_for('index'))


@app.route('/catalog')
def catalog():
    items = Items.query.all()
    if current_user.is_authenticated:
        return render_template('catalog.html', title='VapeLid', url='profile', log=current_user.email, items=items, roll=current_user.roll)
    return render_template('catalog.html', title='VapeLid', url='login', log='Login', items=items, roll='user')


@app.route('/add_item')
@login_required
def add_item():
    if current_user.roll != 'admin':
        return redirect(url_for('index'))
    return render_template('add_item.html',
                           title_page='Add items',
                           action='add_item',
                           button='ADD ITEM')


@app.route('/add_item', methods=['POST'])
@login_required
def add_item_post():
    title = request.form['title']
    content = request.form['content']
    price = request.form['price']
    img = request.form['image']
    category = request.form['category']
    item = Items(title=title, content=content, price=price, img=img, category=category, amount=10)
    db.session.add(item)
    db.session.commit()
    return redirect(url_for('catalog'))


@app.route('/update_item', methods=['GET', 'POST'])
def update_item():
    if current_user.roll != 'admin':
        return redirect(url_for('index'))
    id = request.form['update_id']
    item = Items.query.filter_by(id=id).first()
    return render_template('add_item.html',
                           title_page='Update items',
                           action='update_item1',
                           title=item.title,
                           content=item.content,
                           price=item.price,
                           image=item.img,
                           category=item.category,
                           id=id,
                           button='UPDATE')


@app.route('/update_item1', methods=['POST'])
def update_item_post():
    title = request.form['title']
    content = request.form['content']
    price = request.form['price']
    img = request.form['image']
    category = request.form['category']
    id = request.form['update_id']
    data = Items.query.filter_by(id=id).first()
    data.title = title
    data.content = content
    data.price = price
    data.img = img
    data.category = category
    db.session.commit()
    return redirect(url_for('catalog'))


@app.route('/delete_item', methods=['POST'])
def delete():
    id = request.form['delete_id']
    data = Items.query.filter_by(id=id).first()
    db.session.delete(data)
    db.session.commit()
    return redirect(url_for('catalog'))


if __name__ == '__main__':
    app.run(debug=True)
