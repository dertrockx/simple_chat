from flask import Flask, render_template, request, session, flash, redirect, url_for
from flask_socketio import SocketIO

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import hashlib
from datetime import datetime

import random, string, pprint

from functools import wraps

from flask_wtf import CSRFProtect
from forms import LoginForm, SignupForm

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits))
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
io = SocketIO(app)

class Users(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False)
	email = db.Column(db.String(80), unique=True, nullable=False)
	password = db.Column(db.String(), nullable=False)
	date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
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

class UserSessions(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	session_id = db.Column(db.String(32))
	user = db.Column(db.Integer, db.ForeignKey('users.id'))

	def __repr__(self):
		return "<User {}'s session ID: {}".format(self.user, self.session_id)

class ActiveUsers(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.Integer, db.ForeignKey('users.id'))

	def __repr__(self):
		return "<Active user: {}".format(self.user)

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
		user = Users.query.filter(or_(Users.username == username, Users.email == username)).first()
		if user or user_email:
			if user.check_password(password):
				active_user = ActiveUsers.query.filter_by(user=user.id).first()
				if not active_user:
					active = ActiveUsers(user=user.id)
					db.session.add(active)
					db.session.commit()
					session['logged_in'] = True
					session['user_id'] = user.id
					session['user_username'] = user.username
					flash("Log in successful", "success")
					return redirect(url_for('chat'))
				flash("Uh-oh! It seems that you're still logged-in to another device. Please sign out first", "error")
				return render_template('login.html', form=form)
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
			users = Users.query.filter_by(username=username).all()
			if len(users):
				flash("Username is already taken, consider using a different one", "error")
				return render_template('signup.html', form=form)			
			user = Users(username=username, email=email)
			user.set_password(password)
			db.session.add(user)
			db.session.commit()
			if user is not None:
				session['logged_in'] = True
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
	user = ActiveUsers.query.filter_by(user=session.get('user_id')).first()
	db.session.delete(user)
	db.session.commit()
	session.pop('logged_in')
	session.pop('user_id')
	session.pop('user_username')
	pprint.pprint(session)
	flash("We'll see you again :) Have a nice day!", "success")
	return redirect(url_for('login'))

active_users = []

@io.on('connect')
@is_logged_in
def connect():
	global active_users
	for user in active_users:
		if user.get('user_id') == session.get('user_id'):
			user['SID'] = request.sid	
			return
	user = {
		'user_id': session.get('user_id'),
		'user_username' : session.get('user_username'),
		'SID': request.sid
	}
	active_users.append(user)
	

@io.on('request_users')
def users():
	io.emit('list_users', active_users)

if __name__ == '__main__':
	app.run(debug=True)
