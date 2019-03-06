from flask_marshmallow import Marshmallow
from models import User, Device, Session, Message, ActiveUser

ma = Marshmallow()

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

class MessageSchema(ma.ModelSchema):
	class Meta:
		model = Message
		fields = ('id', 'user_id', 'user', 'message', 'timestamp')	
		
	user = ma.Nested(UserSchema)