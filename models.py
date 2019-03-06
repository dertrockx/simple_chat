from flask_sqlalchemy import SQLAlchemy
import hashlib
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False)
	email = db.Column(db.String(80), unique=True, nullable=False)
	password = db.Column(db.String(), nullable=False)
	date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
	sessions = db.relationship("Session", backref='user_sessions', lazy=True, passive_deletes=True)
	devices = db.relationship('Device', backref='user_devices', lazy=True, passive_deletes=True)
	messages = db.relationship('Message', backref='user_messages', lazy=True, passive_deletes=True)
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


class Message(db.Model):
	__tablename__ = 'messages'
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	user = db.relationship('User', backref='user_message', lazy=True)
	message = db.Column(db.Text, nullable=False)
	timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())

	def __repr__(self):
		return "<User {}'s message: {}".format(self.user.username, self.message)
