import os, json, threading, datetime, time

from functools import wraps
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv

from flask import Flask, jsonify, redirect, render_template, session, url_for, request, Response
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

#import imutils
#from imutils.video import VideoStream
#import cv2

#outputFrame = None
#lock = threading.Lock()

AUTH0_CALLBACK_URL = os.environ.get('AUTH0_CALLBACK_URL')
AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID')
AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET')
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN')
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = os.environ.get('AUTH0_AUDIENCE')

app = Flask(__name__)
app.secret_key = os.environ.get('KEY')

#vs = VideoStream(src=0).start()
#time.sleep(2.0)

#####################################################################################################
### Auth0
#####################################################################################################
@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile',
    },
)

def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/')
    return f(*args, **kwargs)

  return decorated

# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/menu')

#####################################################################################################
### Live Stream
#####################################################################################################

#def record(frameCount):
#	# grab global references to the video stream, output frame, and
#	# lock variables
#	global vs, outputFrame, lock

#	# loop over frames from the video stream
#	while True:
#		# read the next frame from the video stream, resize it,
#		# convert the frame to grayscale, and blur it
#		frame = vs.read()
#		frame = imutils.resize(frame, width=400*2, height=400*2)
#		gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
#		gray = cv2.GaussianBlur(gray, (7, 7), 0)

#		# grab the current timestamp and draw it on the frame
#		timestamp = datetime.datetime.now()
#		cv2.putText(frame, timestamp.strftime(
#			"%A %d %B %Y %I:%M:%S%p"), (10, frame.shape[0] - 10),
#			cv2.FONT_HERSHEY_SIMPLEX, 0.35, (0, 0, 255), 1)

#		# acquire the lock, set the output frame, and release the
#		# lock
#		with lock:
#			outputFrame = frame.copy()

#def generate_live_stream():
#	# grab global references to the output frame and lock variables
#	global outputFrame, lock

#	# loop over frames from the output stream
#	while True:
#		#wait until the lock is acquired
#		with lock:
#			# check if the output frame is available, otherwise skip
#			# the iteration of the loop
#			if outputFrame is None:
#				continue

#			# encode the frame in JPEG format
#			(flag, encodedImage) = cv2.imencode(".jpg", outputFrame)

#			# ensure the frame was successfully encoded
#			if not flag:
#				continue

#		# yield the output frame in the byte format
#		yield(b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + 
#			bytearray(encodedImage) + b'\r\n')


#####################################################################################################
### Routing
#####################################################################################################

@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)

@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

@app.route('/static')
@requires_auth
def play():
    return render_template('static.html')
    
#@app.route('/live')
#@requires_auth
#def live():
#    t = threading.Thread(target=record, args=(32,))
#    t.daemon = True
#    t.start()    
#    return Response(generate_live_stream(), mimetype = "multipart/x-mixed-replace; boundary=frame")
    
@app.route('/menu')
@requires_auth
def dashboard():
    return render_template('menu.html')

@app.route('/')
def home():    
    return redirect("/login", code=302)    

if __name__ == '__main__':    
    app.run(threaded=True, use_reloader=False)
    
#vs.stop()