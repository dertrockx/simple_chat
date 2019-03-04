* Get all active users
* loop through all active users as user
	* if logged_in user is the user
		* get the session_obj based on the user.id
		* if there is:
			1. change the session_obj.sid to request.sid
			2. Add and commit to db
		* else:
			1. create a new session object with the session_id the request.sid, user_id as user.id, and device_id as 		session.get('device_id') 
			2. add and commit to db
		* get the device registered in DB based on the session's device_uuid
		* change the device.session_id to sesion_obj.id
		* add and commit to db
