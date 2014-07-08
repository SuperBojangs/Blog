import os
import re
from string import letters
import string
import random
import hashlib
import webapp2
import jinja2
from google.appengine.ext import db
import json


jinja_env = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_user(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_pass(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_em(email):
	return not email or EMAIL_RE.match(email)



#hashing functions **************************************************
def hash_str(s):
	return hashlib.md5(s).hexdigest() #should change this to HMAC for security

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    
    
    compare1 = make_pw_hash(name,pw,salt)
    
    if compare1 == h:
        return True
    else:
        return False

#************************************************************************
def render_str(template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)


#classes ***************************************************************


class Handler(webapp2.RequestHandler):
	def write(self, *a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self,template, **params):
		params['user'] = self.user
		return render_str(template, **params)
	
	def render(self,template,**kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def initialize(self, *a, **kw):	
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

	def get_cookie(self):
		user_cookie = self.request.cookies.get('user-id')
		if user_cookie:
			cookie_val = check_secure_val(user_cookie)
			if cookie_val:
				user_cookie2 = user_cookie.split('|')[0]
				return user_cookie2	

#------------SIGNUP AND LOGIN----------------------------------------------------
class SignupData(db.Model):
	user_name = db.StringProperty(required=True)
	pass_word = db.StringProperty(required=True)
	e_mail = db.StringProperty



class SignUp(Handler):
	def get(self):
		self.render('signup-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get ('verify')
		email = self.request.get('email')

		valid_username =valid_user(username)
		valid_password = valid_pass(password)
		valid_email = valid_em(email)

		have_error = False
		params = dict()

		if not valid_username:
			have_error = True
			params['error_username'] = "This is not a valid username."

		if not valid_password:
			have_error = True
			params['error_password'] = "This is not a valid password."

		elif password != verify:
			have_error = True
			params['error_verify'] = "Your passwords do not match"

		elif not valid_email:
			have_error= True
			params['error_email'] = "This email is invalid."

		if have_error:
			self.render('signup-form.html',**params)

		else:
			checkusername = SignupData.all()
			checkusername.filter("user_name",username)
			result = checkusername.get()
			if result == None:
				#if not already in database, hash the password
				hashed_password = make_pw_hash(username,password)
				login = SignupData(user_name=username,pass_word=hashed_password,e_mail=email)
				login.put()

				new_user_cookie = str(make_secure_val(username))
				self.response.headers.add_header('Set-Cookie','user-id=%s;Path=/' %new_user_cookie)


				self.redirect('/welcome')

			else:
				have_error=True
				params['error_username'] = "This user already exists."
				self.render('signup-form.html',**params)

			
class Login(Handler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		params = dict()

		if username and password: #if they entered both a user and a password

			#check to see if user and password are in the database
			#pull the database filtered by username
			checksignupdata = SignupData.all()
			checksignupdata.filter("user_name",username)
			result = checksignupdata.get()
			
			if result:    #if data exists
				database_password = result.pass_word # pulls the database hash
				#this_password = make_pw_hash(username, password) #hash the entered credentials
				valid_login = valid_pw(username,password,database_password)
				if valid_login:
					new_user_cookie = str(make_secure_val(username))
					self.response.headers.add_header('Set-Cookie','user-id=%s;Path=/' %new_user_cookie)

					self.redirect('/welcome')
				else:
					params['error_username'] = "Bad user/password combo"
					self.render('login-form.html',**params)
			else:
				params['error_username'] = "No username exists.  Please signup to create an account."
				self.render('login-form.html', **params)
			

		else:
			
			params['error_username'] = "Invalid login"
			self.render('login-form.html',**params)				
							

#--------------------BLOG -------------------------------------------------------------------------

class Blog(db.Model):
	title = db.StringProperty(required=True,multiline=True)
	content = db.StringProperty(required=True,multiline=True)
	created=db.DateTimeProperty(auto_now_add=True)


class MainPage(Handler):
	def get(self):
		self.redirect('/blog')


class BlogFront(Handler):
	def render_front(self):
		username = self.get_cookie()
		if username:
			blogs=db.GqlQuery("SELECT * FROM Blog " "ORDER BY created DESC")
			self.render('blogfront.html',blogs=blogs, username = username)

		else:		
			blogs=db.GqlQuery("SELECT * FROM Blog " "ORDER BY created DESC")
			self.render('blogfront.html', blogs=blogs)
			
		

	def get(self):
		self.render_front()

		
		
		
	

class BlogEntry(Handler):
	def render_blog(self,title="",content="",error=""):
		username = self.get_cookie()
		if username:
			self.render('newpost.html',title=title,content=content,error=error,username=username)
		else:
			self.redirect('/')
	

	def get(self):
		self.render_blog()

	
	def post(self):
		title=self.request.get('subject')
		content=self.request.get('content')

		if title and content:
			b = Blog(title=title,content=content)
			b.put()
			self.redirect('/blog/%s' % str(b.key().id()))

			
		else:
			error = "Please try again."
			self.render_blog(title,content,error)	

class BlogPost(Handler):
    def get(self, post_id):
    	username = self.get_cookie()
    	if username:
    	#get post id
    	#if endswith .json, display in JSON, else display in HTML
        	s = Blog.get_by_id(int(post_id))
        
        	if s:
        		if self.request.url.endswith('.json'):
        			self.format = 'json'
        			self.response.content_type = 'application/json'
        			d = json.dumps({"title":s.title,"content":s.content})
        			self.write(d)

        		else:
        			self.render('postpage.html',s=s,username=username)
        else:
        	self.redirect('/')		
        

class MainpageJson(Handler):
	def get(self):
		self.format = 'json'
		self.response.content_type = 'application/json'
		blogs=db.GqlQuery("SELECT * FROM Blog " "ORDER BY created DESC")
		new_dict = {}

		for blog in blogs:
			json_title = blog.title
			json_content = blog.content
			d = json.dumps({"title":json_title,"content":json_content})
			self.write(d)



class Welcome(Handler):
	def get(self):
		username = self.get_cookie()
		if username:
			self.render('welcome.html', username = username)
		
		else:
			self.redirect('/signup')


class LogOut(Handler):
	def get(self):
		#deletes the cookie and redirects to the signup page
		self.response.delete_cookie('user-id')
		self.redirect('/signup')



application = webapp2.WSGIApplication([('/',MainPage),('/login',Login),('/logout',LogOut),('/signup/?',SignUp),('/welcome',Welcome),('/blog/?',BlogFront),('/newpost/?',BlogEntry),('/blog/([0-9]+)',BlogPost),('/blog/([0-9]+).json',BlogPost),('/blog.json',MainpageJson)],debug=True)