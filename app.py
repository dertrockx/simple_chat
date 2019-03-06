from flask import Flask, render_template, request, session, flash, redirect, url_for
from flask_socketio import SocketIO
from sqlalchemy import or_, desc
import random, string, pprint, uuid
from flask_wtf import CSRFProtect
from forms import LoginForm, SignupForm
from models import db, User, Device, Session, Message, ActiveUser
from schema import ma, UserSchema, DeviceSchema, SessionSchema, MessageSchema, ActiveUserSchema
from wrappers import is_logged_in

app = Flask(__name__)
#app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits))
app.config.from_pyfile('config.py')

db.init_app(app)
csrf = CSRFProtect(app)
io = SocketIO(app)


@app.route('/')
def index():
	return render_template('index.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
	form = LoginForm(request.form)
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		# A complex query
		# SELECT * FROM Users WHERE username = ? OR email = ?
		user = User.query.filter(or_(User.username == username, User.email == username)).first()
		if user or user_email:
			if user.check_password(password):
				active_user = ActiveUser.query.filter_by(user_id=user.id).first()
				if not active_user:
					active = ActiveUser(user_id=user.id)
					db.session.add(active)
					db.session.commit()
				client_UUID = str(uuid.uuid4())
				device = Device(uuid=client_UUID, user_id=user.id)
				db.session.add(device)
				db.session.commit()
				session['device_uuid'] = client_UUID
				session['device_id'] = device.id
				session['logged_in'] = True
				session['user_id'] = user.id
				session['user_username'] = user.username
				flash("Log in successful", "success")
				return redirect(url_for('chat'))
			flash("Passwords do not match!", "error")
			return render_template('login.html', form=form)
		flash("Username not found, consider registering?", "error")
		return render_template('login.html', form=form)
	return render_template('login.html', form=form)

@app.route('/register/', methods=['GET', 'POST'])
def register():
	form = SignupForm(request.form)
	if request.method == 'POST':
		if form.validate():
			username = request.form['username']
			password = request.form['password']
			email = request.form['email']
			users = User.query.filter_by(username=username).all()
			if len(users):
				flash("Username is already taken, consider using a different one", "error")
				return render_template('signup.html', form=form)			
			user = User(username=username, email=email)
			user.set_password(password)
			db.session.add(user)
			db.session.commit()
			active = ActiveUser(user_id=user.id)
			db.session.add(active)
			db.session.commit()

			client_UUID = str(uuid.uuid4())
			uid = Device(uuid=client_UUID, user_id=user.id)
			db.session.add(uid)
			db.session.commit()
			session['device_uuid'] = client_UUID
			if user is not None:
				session['logged_in'] = True
				session['user_id'] = user.id
				session['user_username'] = user.username
				if session:
					flash("Signup successful", "success")
					return redirect(url_for('chat'))
			flash('Something went wrong', "error")
		flash(form.errors, "error")
	return render_template('register.html', form=form)

@app.route('/chat/')
@is_logged_in
def chat():
	return render_template('chat.html')

@app.route('/logout/')
@is_logged_in
def logout():
	try:
		session_ids = Session.query.filter_by(user_id=session.get('user_id')).all()
		active_user = ActiveUser.query.filter_by(user_id=session.get('user_id')).first()
		device = Device.query.filter_by(uuid=session.get('device_uuid')).first()
		
		if len(session_ids) == 1:
			db.session.delete(active_user)
			db.session.commit()
		for sess in session_ids:
			if sess.device.uuid == session.get('device_uuid'):
				db.session.delete(sess)
				db.session.commit()
		if device:
			db.session.delete(device)
			db.session.commit()
		session.pop('logged_in')
		session.pop('user_id')
		session.pop('user_username')
		session.pop('device_id')
		session.pop('device_uuid')
		flash("We'll see you again :) Have a nice day!", "success")
		users()
		return redirect(url_for('login'))
	except Exception as error:
		print(str(error))
		return redirect(url_for('chat'))

@io.on('connect')
@is_logged_in
def connect():
	active_users = ActiveUser.query.all()
	# checks if there's a registered user in the active_user table
	if len(active_users) > 0:
		# loops through the active_users list to find the user
		# currently logged in
		for user in active_users:
			if user.user_id == session.get('user_id'):
				session_obj = Session.query.filter_by(user_id=user.user_id).first()
				session['sid'] = request.sid
				if session_obj:
					session_obj.session_id = request.sid
				else:
					session_obj = Session(session_id=request.sid, user_id =session.get('user_id'), device_id=session.get('device_id'))
				db.session.add(session_obj)
				db.session.commit()
				# first, check if the device is currently registered
				# as active in the DB based off of the session.get('device_uuid')
				user_device = Device.query.filter_by(uuid=session.get('device_uuid')).first()
				if user_device:
					user_device.session_id = session_obj.id
					db.session.add(user_device)
					db.session.commit()
					return


@io.on('request_users')
def users():
	active_users = ActiveUser.query.all()
	users = []
	for u in active_users:
		user_ = UserSchema()
		user = user_.dump(u.user).data
		users.append(user)
	io.emit('list_users', users)

@io.on('request_all_messages')
def list_all_messages():
	mes_ = MessageSchema()
	serialized_messages = []
	messages = Message.query.order_by('timestamp').all()
	for message in messages:
		mes = mes_.dump(message).data
		serialized_messages.append(mes)
	io.emit('list_all_messages', serialized_messages, broadcast=True)

@io.on('send_message')
def send_message(message):
	mes = Message(user_id = session.get('user_id'), message=message)
	db.session.add(mes)
	db.session.commit()
	message = MessageSchema().dump(mes).data
	io.emit("update_message", [message], broadcast=True)


if __name__ == '__main__':
	app.run(debug=True)
