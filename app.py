from flask import Flask, render_template, redirect, url_for,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from datetime import datetime
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
photos = UploadSet('photos', IMAGES)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///q.db'
app.config['UPLOADED_PHOTOS_DEST'] = '/static/photos'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
configure_uploads(app, photos)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)









@app.route('/addPost', methods=['GET', 'POST'])
def addPost():
    if request.method == 'POST' and 'photo' in request.files:
            filename = photos.save(request.files['photo'])
            url = photos.url(filename)
            #u = url[21:36]
            u = url.replace("_uploads", "static")
            post = Post(img=u, author=current_user)
            db.session.add(post)
            db.session.commit()
    return render_template('addPost.html')


    def __repr__(self):
        return '<Post {}>'.format(self.img)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    img = db.Column(db.String(300))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    likes = db.relationship('Likes',backref='likes', lazy='dynamic',passive_deletes=True )
    comments = db.relationship('Comments', backref='comments', lazy='dynamic',passive_deletes=True)
    count_likes = db.Column(db.Integer)


    def __repr__(self):
        return '<Post {}>'.format(self.img)

    
class Likes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id',ondelete='CASCADE'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id',ondelete='CASCADE'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<Likes {}>'.format(self.id)

class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id',ondelete='CASCADE'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id',ondelete='CASCADE'))
    body = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

@app.route('/explore/')
@login_required
def explore():
    global posts
    posts = list()
    users = User.query.filter_by().all()
    global counter_end
    
    posts = Post.query.filter_by().all()
    return render_template('explore.html', title='Explore', posts=posts)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/search')
@login_required
def search():
    if not g.search_form.validate():
        return redirect(url_for('/'))
    
    page = request.args.get('page', 1, type=int)
    User.reindex()
    users, total = User.search(g.search_form.q.data, page,10)
    
    return render_template('search.html', title='Search', users=users)



if __name__ == '__main__':
    app.run(debug=True)