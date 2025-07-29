import os
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, select, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login


# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app)



class User(UserMixin, db.Model):
    __tablename__ = "users"
    
    id: Mapped[int] = mapped_column(Integer,primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    
    posts = relationship("BlogPost",back_populates="author")
    comments = relationship("Comment", back_populates="author")
    
    def __init__(self, email, password, name):
        self.email = email
        self.password = password
        self.name = name



class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User",back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String, nullable=False)

    post_id: Mapped[int] = mapped_column(Integer, ForeignKey('blog_posts.id'), nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")
    
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    author = relationship("User",back_populates="comments")
    
    def __init__(self, text, post_id, author_id):
        self.text = text
        self.post_id = post_id
        self.author_id = author_id

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User,user_id)

def admin_only(func):
    def admin_wrapper(*args,**kwargs):
        if not current_user.is_authenticated or not current_user.get_id() == '1':
            return abort(403)
        return func(*args,*kwargs)
    admin_wrapper.__name__ = func.__name__
    return admin_wrapper


@app.route('/register', methods = ['GET','POST'])
def register():
    form = RegisterForm()
    if not form.validate_on_submit():
        return render_template("register.html", form = form)
    
    entered_email = form.email.data
    email_list = [user.email for user in db.session.execute(select(User)).scalars().all()]
    if entered_email in email_list:
        flash('Email already exists! Login instead.')
        return redirect(url_for('login'))
    
    
    hashed_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
    new_user = User(
        email=entered_email,
        password=hashed_password,
        name=form.name.data
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user)
    return redirect(url_for('get_all_posts'))


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        entered_email = form.email.data
        entered_password = form.password.data
        
        requested_user = db.session.execute(select(User).where(User.email == entered_email)).scalar()
        
        if requested_user is None:
            flash('That email does not exist. Try again')
            return redirect(url_for('login'))
        
        if not check_password_hash(requested_user.password,entered_password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        
        login_user(requested_user)
        return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods = ["GET","POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    
    if not comment_form.validate_on_submit():
        return render_template("post.html", post=requested_post, form = comment_form)
    
    if not current_user.is_authenticated:
        flash('Only registered and logged in users can comment.')
        return redirect(url_for('login'))
        
    new_comment = Comment(
        text = comment_form.comment.data,
        post_id=post_id,
        author_id=current_user.id
    )
    
    db.session.add(new_comment)
    db.session.commit()
    
    return redirect(url_for('show_post', post_id=post_id))


# TODO: Use a decorator so only an admin user can create a new post


@app.route("/new-post", methods=["GET", "POST"])
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
            date=date.today().strftime("%B %d, %Y")
        )
        
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post

@admin_only
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug = False)
