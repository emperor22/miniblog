from flask import Flask, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy, BaseQuery
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import LoginManager, login_user, current_user, logout_user, login_required,UserMixin
from flask_bcrypt import Bcrypt
from flaskext.markdown import Markdown
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
from sqlalchemy_searchable import SearchQueryMixin
from sqlalchemy_utils.types import TSVectorType
from sqlalchemy_searchable import make_searchable
import os
import pyotp
import time
import timeago


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
secret = os.environ.get('secret')
admin_username = os.environ.get('admin')
app.config['SECRET_KEY'] = 'c2efeca863779384f7363e4a02e0510c'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
totp = pyotp.TOTP(secret, interval=30)
otp = totp.now()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
Markdown(app)
make_searchable(db.metadata)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


############################
## Models Classes ##########
############################

class TagTable(db.Model):
    __tablename__ = 'tags_table'
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), primary_key=True)
    tags_id = db.Column(db.Integer, db.ForeignKey('tags.id'), primary_key=True)

class PostQuery(BaseQuery, SearchQueryMixin):
    pass

class Post(db.Model):
    __tablename__ = 'post'
    query_class = PostQuery

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    tags = db.relationship('Tags', secondary='tags_table', backref=db.backref('posts', lazy='dynamic'))
    category = db.Column(db.String(15), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    published = db.Column(db.Boolean, nullable=False)
    featured = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post_parent', lazy=True)
    search_vector = db.Column(TSVectorType('title', 'content'))
    def __repr__(self):
        return f"Post('{self.title}', '{self.category}', '{self.date_posted}', '{self.featured}')"

class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(20))
    content = db.Column(db.String(500))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    parent = db.Column(db.Integer, db.ForeignKey('post.id'))

    def __repr__(self):
        return f"Comment('{self.author}', '{self.content}')"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)


    def __repr__(self):
        return f"User('{self.username}', '{self.name}', '{self.image_file}')"

############################
## Form Classes ############
############################

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    tags = StringField('Tags')
    category = SelectField('Category',
                                    choices=[('', ''),('tech', 'Tech'), ('politics', 'Politics'),
                                            ('rants', 'Rants'), ('shitpost', 'Shitpost'),
                                            ('analytics', 'Analytics'), ('project', 'Project')], validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    published = BooleanField('Published')
    submit = SubmitField('Post')

    def validate_tags(self, tags):
        if len(set([i.replace(' ', '') for i in tags.data.split(';')])) > 5:
            raise ValidationError('You can only insert 5 unique tags at most.')
        for i in tags.data.split(';'):
            if len(i) > 20:
                raise ValidationError('One tag has a maximum length of 10 characters.')

class FilterForm(FlaskForm):
    category_filter = SelectField('category',
                                    choices=[('', 'All'),('tech', 'Tech'), ('politics', 'Politics'),
                                            ('rants', 'Rants'), ('shitpost', 'Shitpost'),
                                            ('analytics', 'Analytics'), ('project', 'Project')])
    submit_filter = SubmitField('Filter')

class SearchForm(FlaskForm):
    query = StringField('Search')
    submit = SubmitField('')

class CommentForm(FlaskForm):
    author = StringField(validators=[DataRequired(), Length(max=20)])
    content = TextAreaField(validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Submit')

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    name = StringField('Username',
                        validators=[DataRequired(), Length(min=2, max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    otp = StringField('OTP', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists')
    def validate_otp(self, otp):
        otp = totp.verify(otp.data)
        if not otp:
            raise ValidationError('Wrong OTP')

class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
#    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


############################
## Routes ##################
############################

@app.before_first_request
def initiate_index():
    db.configure_mappers()
    db.create_all()
    db.session.commit()

@app.route("/", methods=['GET', 'POST'])
def index():
    form = FilterForm()
    page=request.args.get('page', 1, type=int)
    featured_posts=Post.query.order_by(Post.date_posted.desc()).filter_by(published=True, featured=True).limit(3).all()
    posts=Post.query.order_by(Post.date_posted.desc()).filter_by(published=True).paginate(page=page, per_page=3)
    if form.validate():
        return redirect(url_for('category', categoryname=form.category_filter.data))
    return render_template("index.html", posts=posts, form=form, featured_posts=featured_posts)


@app.route("/post/category/<string:categoryname>", methods=['GET', 'POST'])
def category(categoryname):
    form = FilterForm()
    categoryname=categoryname
    page=request.args.get('page', 1, type=int)
    posts=Post.query.order_by(Post.date_posted.desc()).filter_by(published=True, category=categoryname).paginate(page=page, per_page=3)
    if form.validate_on_submit():
        if form.category_filter.data:
            return redirect(url_for('category', categoryname=form.category_filter.data))
        else:
            return redirect(url_for('index'))
    else:
        form.category_filter.data = categoryname
    return render_template("category.html", posts=posts, form=form, categoryname=categoryname)

@app.route("/post/user/<int:user_id>/category/<string:categoryname>", methods=['GET', 'POST'])
def user_post_category(user_id, categoryname):
    form = FilterForm()
    categoryname=categoryname
    user_id=user_id
    page=request.args.get('page', 1, type=int)
    user=User.query.filter_by(id=user_id).first_or_404()
    posts=Post.query.order_by(Post.date_posted.desc()).filter_by(published=True, category=categoryname, author=user).paginate(page=page, per_page=3)
    if form.validate_on_submit():
        if form.category_filter.data:
            return redirect(url_for('user_post_category', user_id=user_id, categoryname=form.category_filter.data))
        else:
            return redirect(url_for('user_post', user_id=user_id))
    else:
        form.category_filter.data = categoryname
    return render_template("user_post_category.html", posts=posts, form=form, user=user, user_id=user_id, categoryname=categoryname)

@app.route("/post/user/<int:user_id>", methods=['GET', 'POST'])
def user_post(user_id):
    form = FilterForm()
    user_id=user_id
    page=request.args.get('page', 1, type=int)
    user=User.query.filter_by(id=user_id).first_or_404()
    posts=Post.query.order_by(Post.date_posted.desc()).filter_by(author=user, published=True).paginate(page=page, per_page=3)
    if form.validate_on_submit():
        return redirect(url_for('user_post_category', user_id=user_id, categoryname=form.category_filter.data))
    return render_template("user_post.html", user=user, posts=posts, form=form)

@app.route("/drafts")
@login_required
def drafts():
    page=request.args.get('page', 1, type=int)
    posts=Post.query.order_by(Post.date_posted.desc()).filter_by(published=False, author=current_user).paginate(page=page, per_page=5)
    return render_template("drafts.html", posts=posts)

@app.route("/tag/<string:tagname>")
def tagged_posts(tagname):
    if tagname == '':
        abort(404)
    page=request.args.get('page', 1, type=int)
    tag = Tags.query.filter_by(name=tagname).first()
    if not tag:
        abort(404)
    posts = tag.posts.filter_by(published=True).paginate(page=page, per_page=6)

    return render_template("tag_posts.html", posts=posts, tag=tag)

@app.route("/login", methods=['GET', 'POST'])
@app.route("/login/", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form1 = LoginForm()
    form2 = RegistrationForm()
    if form1.validate_on_submit():
        user = User.query.filter_by(username=form1.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form1.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
#        else:
#            flash('Login Unsuccessful. Please check email and password', 'danger')
    if form2.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form2.password.data).decode('utf-8')
        user = User(username=form2.username.data, name=form2.name.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        #flash('Your account has been created! You are now able to log in', 'success')
        #return redirect(url_for('login'))
    return render_template('login2.html', title='Login Page', form1=form1, form2=form2)

@app.route("/logout")
@app.route("/logout/")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/search")
def search():
    query = request.args.get('q', ' ')
    posts = Post.query.search(query).filter_by(published=True)

    return render_template("search.html", posts=posts, keyword=query)

@app.route("/post_it", methods=['GET', 'POST'])
@login_required
def post_it():
    form = PostForm()
    published_check = False

    def tag_append(post):
        if form.tags.data[-1] == ';':
            form.tags.data = form.tags.data[:-1]
        tag_names = sorted(list(set([i.replace(' ', '') for i in form.tags.data.split(';')])))
        for name in tag_names:
            tag = Tags.query.filter_by(name=name).first()
            if tag:
                tag.posts.append(post)
            else:
                new_tag = Tags(name=name)
                db.session.add(new_tag)
                new_tag.posts.append(post)


    if form.validate_on_submit():

        post = Post(title=form.title.data, author=current_user, category = form.category.data,
                    content=form.content.data, published=form.published.data, featured=False)
        db.session.add(post)
        tag_append(post)
        db.session.commit()


        return redirect(url_for('index'))
    return render_template("post_it.html", legend='Create Post', form=form, published_check=published_check)

@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def post(post_id):
    all_posts = Post.query.filter_by(published=True).order_by(Post.date_posted.desc()).limit(3).all()
    admin = User.query.filter_by(username=admin_username).first()
    post = Post.query.filter_by(id=post_id).first()
    form = CommentForm()
    comments = Comment.query.order_by(Comment.date_posted).filter_by(post_parent=post).all()
    tags = post.tags
    all_tags = Tags.query.order_by(Tags.name).all()

    comment_count= Comment.query.filter_by(post_parent = post).count()
    date_posted=post.date_posted.strftime("%B %d, %Y")

    categories = ['tech', 'politics', 'rants', 'shitpost','analytics' ,'project']
    def categoryf(name):

        return Post.query.filter_by(category=name, published=True).count()

    def time_diff(a):
        return timeago.format(a, datetime.utcnow())

    if post.published == False and post.author != current_user:
        abort(404)

    if form.validate_on_submit():
        comment = Comment(author=form.author.data, content=form.content.data, parent=post.id)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('post', post_id=post_id))


    return render_template("post.html", post=post, all_posts=all_posts,
                            date_posted=date_posted, categoryf=categoryf, 
                            categories=categories, admin=admin, comment_count=comment_count,
                            form=form, comments=comments, time_diff=time_diff, tags=tags, all_tags=all_tags)


@app.route("/post/<int:post_id>/edit", methods=['GET', 'POST'])
@login_required
def editpost(post_id):
    post = Post.query.get_or_404(post_id)
    admin = User.query.filter_by(username=admin_username).first()
    published_check = post.published
    if post.author != current_user and admin != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.category = form.category.data
        post.content = form.content.data
        post.published = True
        if published_check == False:
            post.published = form.published.data
            post.date_posted = datetime.utcnow()
        db.session.commit()
        #flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))

    elif request.method == 'GET':
        form.title.data = post.title
        form.category.data = post.category
        form.content.data = post.content
        form.published.data = post.published
    return render_template('post_it.html', legend='Edit Post', form=form, published_check=published_check)

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def deletepost(post_id):
    post = Post.query.get_or_404(post_id)
    admin = User.query.filter_by(username=admin_username).first()
    if post.author == current_user or admin.is_authenticated:
        db.session.delete(post)
        db.session.commit()
    else:
        abort(403)
    #flash('Your post has been deleted!', 'success')
    return redirect(url_for('index'))

@app.route("/post/<int:post_id>/feature_post", methods=['POST'])
@login_required
def feature_post(post_id):
    post = Post.query.get_or_404(post_id)
    admin = User.query.filter_by(username=admin_username).first()
    if admin.is_authenticated:
        post.featured = True
        db.session.commit()
    else:
        abort(403)
    #flash('Your post has been deleted!', 'success')
    return redirect(url_for('index'))


if __name__=="__main__":
    app.run(debug=True)
