from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

## connect to gravatar
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# configure a login manager
login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view= 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id= db.Column(db.Integer, primary_key=True)
    email= db.Column(db.String(250), unique=True, nullable=False)
    password= db.Column(db.String(250), nullable=False)
    user_name= db.Column(db.String(250), nullable=False, unique=True)
    posts= db.relationship('BlogPost', back_populates='author')
    comments=db.relationship('Comment', back_populates='author')



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250))
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250))
    comments= db.relationship('Comment', backref='post')


class Comment(UserMixin, db.Model):
    __tablename__='comments'
    
    id= db.Column(db.Integer, primary_key=True)
    text= db.Column(db.String(350), nullable=False)
    author_id= db.Column(db.Integer, db.ForeignKey('users.id'))
    author= db.relationship('User', back_populates='comments' )
    post_id= db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


db.create_all()


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)

        else:
            return abort(403)
    return wrapper


@app.route('/')
def get_all_posts():

    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form= RegisterForm()

    if form.validate_on_submit():

        # check if the email is exist in the database
        if User.query.filter_by(email= form.email.data).first():
            flash("you've already signed up with that email, login instead")
            return redirect(url_for('login'))

        else:   # the user is fresh

            hash_password= generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)

            user= User(
                email=form.email.data,
                password=hash_password,
                user_name=form.user_name.data
            )

            try:
                db.session.add(user)
                db.session.commit()
                login_user(user)
                flash('you successfully registered, thank you')
                return redirect(url_for('get_all_posts'))

            except:
                flash('sorry, there is a problem, try again plaease')
                return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():

        input_email = form.email.data
        user = User.query.filter_by(email=input_email).first()

        if user:

            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))

            else:
                flash('the password is wrong, try again?')
                return redirect (url_for('login'))

        else:
            flash('the email does not exist?, you have to register!')
            return redirect(url_for('register'))


    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form= CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments_post = Comment.query.filter_by(post_id=post_id).all()

    if form.validate_on_submit():

        if current_user.is_authenticated:
            new_comment= Comment(
                text= form.text.data,
                author= current_user,
                post= requested_post,
            )

            try:
                db.session.add(new_comment)
                db.session.commit()

                return render_template('post.html')
            except:
                return 'there is a problem'
        else:
            flash('you should login first to comment')
            return redirect(url_for('login'))
        
    return render_template("post.html", post=requested_post, form=form, comments= comments_post)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),

        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    except:
        return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)
