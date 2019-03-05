from flask import Flask, render_template, request, session, flash, redirect, url_for
from flask_socketio import SocketIO

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_

from flask_marshmallow import Marshmallow

import hashlib
from datetime import datetime

import random, string, pprint, uuid

from functools import wraps

from flask_wtf import CSRFProtect
from forms import LoginForm, SignupForm



app = Flask(__name__)
#app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits))
app.config['SECRET_KEY'] = 'secret'
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
io = SocketIO(app)
ma = Marshmallow(app)

class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False)
	email = db.Column(db.String(80), unique=True, nullable=False)
	password = db.Column(db.String(), nullable=False)
	date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
	sessions = db.relationship("Session", backref='user_sessions', lazy=True, passive_deletes=True)
	devices = db.relationship('Device', backref='user_devices', lazy=True, passive_deletes=True)
	active = db.relationship("ActiveUser", backref='user_active', lazy=True, uselist=False)
	def __repr__(self):
		return '<User {}>'.format(self.username)

	def set_password(self, password):
		hasher = hashlib.sha256()
		hasher.update((password).encode('utf-8'))
		self.password = hasher.hexdigest()
		return self.password

	def check_password(self, password):
		hasher = hashlib.sha256()
		hasher.update((password).encode('utf-8'))
		password = hasher.hexdigest()
		return (password == self.password)

class Session(db.Model):
	__tablename__ = 'sessions'
	id = db.Column(db.Integer, primary_key=True)
	session_id = db.Column(db.String(32), nullable=False)

	user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
	user = db.relationship('User', lazy=True, backref='user_sessions', foreign_keys=[user_id])

	device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
	device = db.relationship('Device', backref='device_session', lazy=True, uselist=False, foreign_keys=[device_id])

	def __repr__(self):
		return "<User {}\n\tID: {}\n\tSession: {}\n\tDevice: {}\n\tDevice UUID: {}\n".format(self.user.username, self.id, self.session_id, self.device.id, self.device.uuid)

class Device(db.Model):
	__tablename__ = 'devices'
	id = db.Column(db.Integer, primary_key=True)

	session_id = db.Column(db.Integer, db.ForeignKey('sessions.id', ondelete='CASCADE'))
	session = db.relationship('Session', backref='device_session', lazy=True, uselist=False, foreign_keys=[session_id])

	user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
	user = db.relationship('User', backref='user_devices', lazy=True, foreign_keys=[user_id])

	uuid = db.Column(db.String(32), nullable=False)
	
	def __repr__(self):
		return "<User {}'s device:\n\tID: {}\n\tUUID: {}\n".format(self.user_id, self.id, self.uuid)

class ActiveUser(db.Model):
	__tablename__ = 'active_users'
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	user = db.relationship('User', backref='user', lazy=True, uselist=False)

	def __repr__(self):
		return "<Active user: {}".format(self.user)



'''
	Model schemas
'''


class SessionSchema(ma.ModelSchema):
	class Meta:
		model = Session
		fields = ('id', 'session_id', 'device_id',)

class DeviceSchema(ma.ModelSchema):
	
	class Meta:
		model = Device
		fields = ('id', 'session', 'uuid',)

class ActiveUserSchema(ma.ModelSchema):

	class Meta:
		model = ActiveUser
		fields = ('id', 'user_id')

class UserSchema(ma.ModelSchema):

	class Meta:
		fields = ('username', 'email', 'id', 'devices', 'sessions')
		model = User
	sessions = ma.Nested(SessionSchema, many=True)
	devices = ma.Nested(DeviceSchema, many=True)
'''
class Messages(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	message = db.Column(db.Text, nullable=False)
	user_id_from = db.Column(db.Integer, db.ForeignKey('users.id'))
	user_from = db.relationship('Users', backref=db.backref('sent_messages'), lazy=True)
	user_id_to = db.Column(db.Integer, db.ForeignKey('users.id'))
	user_to = db.relationship('Users', backref=db.backref('received_messages'), lazy=True)
	
	def __repr__(self):
		return '<Message {}>'.format(self.message)
'''



def is_logged_in(function):
	@wraps(function)
	def wrap(*args, **kwargs):
		try:
			if session['logged_in']:
				return function(*args, **kwargs)
		except KeyError:
			flash("You must be logged-in to do that!", "error")
			return redirect(url_for('login'))
	return wrap


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
		print(device)
		if len(session_ids) == 1:
			db.session.delete(active_user)
			db.session.commit()
		for sess in session_ids:
			if sess.device.uuid == session.get('device_uuid'):
				db.session.delete(sess)
				db.session.commit()
		if device:
			print("Deleting device...")
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

if __name__ == '__main__':
	app.run(debug=True)
