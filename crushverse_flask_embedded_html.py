from flask import Flask, request, redirect, url_for, render_template_string, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
import time, secrets

# ---------------- App Setup ----------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crushverse.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------- Models ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    points = db.Column(db.Integer, default=0)
    crush_mode = db.Column(db.Boolean, default=False)
    theme = db.Column(db.String(10), default='light')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    ts = db.Column(db.Integer, default=lambda: int(time.time()))

class Interaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer)
    to_user_id = db.Column(db.Integer)
    type = db.Column(db.String(50))
    ts = db.Column(db.Integer, default=lambda: int(time.time()))

db.create_all()

# ---------------- Login Manager ----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- Templates ----------------
TEMPLATES = {
    'index': """
    <h1>Crushverse</h1>
    {% if current_user.is_authenticated %}
    <p>Hello {{ current_user.username }} | Points: {{ current_user.points }}</p>
    <a href='/feed'>Feed</a> | <a href='/crushverse'>Crushverse</a> | <a href='/logout'>Logout</a>
    {% else %}
    <a href='/login'>Login</a> | <a href='/signup'>Sign Up</a>
    {% endif %}
    """,
    'login': """
    <h2>Login</h2>
    <form method='POST'>
    <input name='username' placeholder='Username'>
    <input name='password' type='password' placeholder='Password'>
    <button>Login</button>
    </form>
    """,
    'signup': """
    <h2>Signup</h2>
    <form method='POST'>
    <input name='username' placeholder='Username'>
    <input name='password' type='password' placeholder='Password'>
    <button>Sign Up</button>
    </form>
    """,
    'feed': """
    <h2>Feed</h2>
    <form method='POST'>
    <textarea name='content'></textarea>
    <button>Post</button>
    </form>
    {% for post in posts %}
    <div><b>{{ post.user.username }}</b>: {{ post.content }}</div>
    {% endfor %}
    <a href='/'>Home</a>
    """,
    'crushverse': """
    <h2>Crushverse Dashboard</h2>
    <p>Username: {{ current_user.username }}</p>
    <p>Points: {{ current_user.points }} | Crush Mode: {{ 'On' if current_user.crush_mode else 'Off' }}</p>
    <form method='POST' action='/toggle_crush'>
    <button type='submit'>Toggle Crush Mode</button>
    </form>
    <a href='/interact'>Send Interaction</a><br>
    <a href='/chat'>Chat</a><br>
    <a href='/'>Home</a>
    """,
    'interact': """
    <h2>Send Interaction</h2>
    <form method='POST'>
    <input name='to_user' placeholder='Send To Username'>
    <select name='type'>
        {% for t in interactions %}<option>{{ t }}</option>{% endfor %}
    </select>
    <button>Send</button>
    </form>
    <a href='/crushverse'>Back</a>
    """,
    'chat': """
    <h2>Global Chat</h2>
    <input id='msg' placeholder='Type message'>
    <button onclick='sendMessage()'>Send</button>
    <div id='messages'></div>
    <script src='https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js'></script>
    <script>
        var socket = io();
        socket.on('message', function(data){
            var div = document.getElementById('messages');
            div.innerHTML += '<div>'+data.user+': '+data.msg+'</div>';
        });
        function sendMessage(){
            var input=document.getElementById('msg');
            socket.emit('message', {user: '{{ current_user.username }}', msg: input.value});
            input.value='';
        }
    </script>
    <a href='/crushverse'>Back</a>
    """
}

INTERACTIONS = ['heart_signal','eye_contact','secret_smile','vibe_ping','soft_wave','spark_request','warm_note','aura_touch','tiny_confession','sweet_echo','heartbeat_sync','rose_drop','star_gift','anonymous_poem','cute_hint','daydream_send','warm_emoji','mystery_box','blush_reaction','crush_ping','pulse_drop','color_message']

# ---------------- Routes ----------------
@app.route('/')
def index():
    return render_template_string(TEMPLATES['index'])

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=='POST':
        u = request.form['username']
        p = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=u, password=p)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template_string(TEMPLATES['signup'])

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = request.form['username']
        p = request.form['password']
        user = User.query.filter_by(username=u).first()
        if user and bcrypt.check_password_hash(user.password, p):
            login_user(user)
            return redirect(url_for('index'))
    return render_template_string(TEMPLATES['login'])

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/feed', methods=['GET','POST'])
@login_required
def feed():
    if request.method=='POST':
        content = request.form['content']
        post = Post(user_id=current_user.id, content=content)
        db.session.add(post)
        db.session.commit()
    posts = Post.query.order_by(Post.ts.desc()).all()
    return render_template_string(TEMPLATES['feed'], posts=posts)

@app.route('/crushverse')
@login_required
def crushverse():
    return render_template_string(TEMPLATES['crushverse'])

@app.route('/toggle_crush', methods=['POST'])
@login_required
def toggle_crush():
    current_user.crush_mode = not current_user.crush_mode
    db.session.commit()
    return redirect(url_for('crushverse'))

@app.route('/interact', methods=['GET','POST'])
@login_required
def interact():
    if request.method=='POST':
        to_u = User.query.filter_by(username=request.form['to_user']).first()
        if to_u:
            inter = Interaction(from_user_id=current_user.id, to_user_id=to_u.id, type=request.form['type'])
            current_user.points += 5
            db.session.add(inter)
            db.session.commit()
            return redirect(url_for('crushverse'))
    return render_template_string(TEMPLATES['interact'], interactions=INTERACTIONS)

# ---------------- SocketIO Events ----------------
@socketio.on('message')
def handle_message(data):
    emit('message', data, broadcast=True)

# ---------------- Run ----------------
if __name__=='__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=8000)
