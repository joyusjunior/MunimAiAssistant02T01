import os
from flask import Flask, render_template, redirect, url_for, session, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests
from googleapiclient.discovery import build
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id_, email):
        self.id = id_
        self.email = email

# Google OAuth setup
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
client_secrets_file = "client_secret.json"
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", 
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/drive.file"],
    redirect_uri="http://localhost:5000/callback"
)

@login_manager.user_loader
def load_user(user_id):
    if 'user' in session:
        user_data = session['user']
        return User(user_data['id'], user_data['email'])
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    
    # Get user info
    userinfo = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
    
    # Create user
    user = User(id_=userinfo['id'], email=userinfo['email'])
    login_user(user)
    
    # Store user in session
    session['user'] = {
        'id': userinfo['id'],
        'email': userinfo['email'],
        'name': userinfo.get('name', '')
    }
    
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Create a Drive service
    credentials = google.oauth2.credentials.Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=credentials)
    
    # List user's files (just for demo)
    results = drive_service.files().list(
        pageSize=10, fields="files(id, name)").execute()
    files = results.get('files', [])
    
    return render_template('dashboard.html', user=session['user'], files=files)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # SSL required for Google OAuth
