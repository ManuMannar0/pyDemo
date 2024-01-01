# -*- coding: utf-8 -*-

import requests
import threading
import time
import json
from flask import Flask, request, redirect, render_template, session, url_for, jsonify
import pandas as pd
#import joblib
#from sklearn.ensemble import RandomForestRegressor
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from peewee import Model, CharField, SqliteDatabase, BooleanField
from datetime import datetime, timezone
from flask_socketio import SocketIO
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('ISS_PY_KEY')
db = SqliteDatabase('db/isspy.db')
socketio = SocketIO(app, async_mode='threading', logger=True, engineio_logger=True)
oauth = OAuth(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='http://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

class User(Model, UserMixin):
    username = CharField(unique=True, null=True)
    password_hash = CharField(null=True)
    email = CharField(unique=True, null=True)
    is_oauth = BooleanField(default=False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    class Meta:
        database = db

@login_manager.user_loader
def load_user(user_id):
    return User.get_or_none(User.id == int(user_id))

def iss_tracker():
    print('iss_tracker def')
    while True:
        print('iss_tracker while')
        position = get_iss_position()
        socketio.emit('update_position', {'latitude': position['latitude'], 'longitude': position['longitude']})
        print(position['latitude'], position['longitude'])
        time.sleep(10)  

def get_iss_position():
    print('get_iss_position def')
    url = "https://api.wheretheiss.at/v1/satellites/25544"
    payload={}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)
    location = json.loads(response.text)
    print('get_iss_position location: ', location)
    return(location)

def find_or_create_google_user(userinfo):
    email = userinfo['email']
    user = User.get_or_none(User.email == email)
    if not user:
        user = User.create(email=email, is_oauth=True) 
    return user

@app.errorhandler(404)
def page_not_found(erro):
    return redirect(url_for('root'))

@app.route('/')
@login_required
def root():
    return render_template('homepage.html')

@app.route('/open_street_map', methods=['POST'])
@login_required
def open_street_map():
    city_name = request.form['city_name']
    response = requests.get(f"https://nominatim.openstreetmap.org/search?city={city_name}&format=json")
    cities = response.json()
    if len(cities):
        return render_template('homepage.html', cities=cities)
    else:
        return render_template('homepage.html', messages=response)

@app.route('/iss', methods=['POST'])
@login_required
def iss():
    lat = request.form['lat']
    lon = request.form['lon']
    atLeastSec = 30
    forNextDays = 7
    alt = 0
    satellite = 25544 #ISS
    response = requests.get(f"https://api.n2yo.com/rest/v1/satellite/visualpasses/{satellite}/{lat}/{lon}/{alt}/{forNextDays}/{atLeastSec}/&apiKey={os.getenv('N2YO_KEY')}")
    data = response.json()
    def format_timestamp(unix_timestamp):
        return datetime.fromtimestamp(unix_timestamp, timezone.utc).strftime('%H:%M on %d-%m-%Y')
    descriptions = []
    for pass_info in data["passes"]:
        start_time = format_timestamp(pass_info["startUTC"])
        start_direction = pass_info["startAzCompass"]
        max_time = format_timestamp(pass_info["maxUTC"])
        max_direction = pass_info["maxAzCompass"]
        description = (
            f"To observe the ISS, look towards {start_direction} at {start_time}. "
            f"The highest elevation point will be towards {max_direction}."
        )
        descriptions.append(description)
    return render_template('homepage.html', messages=descriptions)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_or_none(User.username == username)
        if user and user.password_hash and user.check_password(password):
            login_user(user)
            return redirect('/')
        elif user and user.is_oauth:
            login_user(user)
            return redirect('/')
        else:
            return redirect('/')
    return render_template('login.html')


@app.route('/login/google')
def logingoogle():
    redirect_uri = url_for('authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorized')
def authorized():
    google.authorize_access_token()
    token = google.token
    session['google_token'] = token 
    userinfo = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
    user = find_or_create_google_user(userinfo)
    login_user(user)
    return redirect(url_for('root'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    user_id = current_user.id if not current_user.is_anonymous else None
    is_google_user = current_user.is_oauth if not current_user.is_anonymous else False
    is_oauth_user = current_user.is_oauth if not current_user.is_anonymous else False
    logout_user()
    if is_google_user:
        User.delete().where(User.id == user_id).execute()
    if 'google_token' in session:
        session.pop('google_token', None)
    return redirect('/login')

@app.route('/users')
@login_required
def users():
    all_users = User.select()
    return render_template('users.html', users=all_users)

@app.route('/documentation')
@login_required
def documentation():
    return render_template('documentation.html')

@app.route('/users/new', methods=['GET', 'POST'])
def new_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.get_or_none(User.username == username)
        if existing_user:
            return 'Username already exists'
        user = User(username=username)
        user.set_password(password)
        user.save()
        return redirect('/users')
    return render_template('new_user.html')

if __name__ == '__main__':
    db.connect()
    db.create_tables([User], safe=True)
    threading.Thread(target=iss_tracker, daemon=True).start()
    socketio.run(app)
    print('end py code')
    #socketio.run(app, debug=True, port=5001)
    #app.run(debug=True, port=8080)