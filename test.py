from app import User, Device, Session, ActiveUser
from app import UserSchema, DeviceSchema, SessionSchema, ActiveUserSchema
from app import db


user = User.query.filter_by(id=1).first()
user_ = UserSchema()
data = user_.dump(user).data
print(data)

session = Session.query.filter_by(user_id=user.id).first()
ses_ = SessionSchema()
data = ses_.dump(session).data
print(data)

device = Device.query.filter_by(user_id=user.id).first()
dev_ = DeviceSchema()
data = dev_.dump(device).data
print(data)

active = ActiveUser.query.filter_by(user_id=user.id).first()
act_ = ActiveUserSchema()
data = act_.dump(active).data
print(data)