from functools import wraps
from flask import session, flash, redirect, url_for

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
