from flask import Flask, request, redirect, render_template
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from peewee import Model, CharField, SqliteDatabase
import requests
from datetime import datetime, timedelta

secret_key = 'asf4fAG4gadgmu875fdDGG'
weather_key = 'ef3f883ea14e274c1bf43027321af0fc'

# Configurazione dell'app Flask e del database
app = Flask(__name__)
app.config['SECRET_KEY'] = weather_key
db = SqliteDatabase('myapp.db')

# Configurazione di Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modello utente con Peewee
class User(Model, UserMixin):
    username = CharField(unique=True)
    password_hash = CharField()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    class Meta:
        database = db

# Funzione di caricamento utente per Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.get_or_none(User.id == int(user_id))

# Route per la homepage
@app.route('/')
@login_required
def root():
    lat, lon = 45.7372, 7.3206
    timestamp = int((datetime.now() - timedelta(days=365 * 10)).timestamp())
    api_key = 'ef3f883ea14e274c1bf43027321af0fc'
    url = f"https://history.openweathermap.org/data/3.0/history/timemachine?lat={lat}&lon={lon}&dt={timestamp}&appid={api_key}"
    response = requests.get(url)
    weather_data = response.json()
    print(weather_data)

    return render_template('homepage.html', weather_data=weather_data)

# Route per il login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.get_or_none(User.username == username)
        if user and user.check_password(password):
            login_user(user)
            return redirect('/')
        else:
            return 'Invalid username or password'

    return render_template('login.html')

# Route per il logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')

# Route per visualizzare gli utenti
@app.route('/users')
@login_required
def users():
    all_users = User.select()
    return render_template('users.html', users=all_users)

# Route per creare un nuovo utente
@app.route('/users/new', methods=['GET', 'POST'])
def new_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verifica se l'utente esiste già
        existing_user = User.get_or_none(User.username == username)
        if existing_user:
            return 'Username already exists'

        # Crea un nuovo utente e salvalo
        user = User(username=username)
        user.set_password(password)
        user.save()

        return redirect('/users')

    return render_template('new_user.html')

# Inizializzazione del database e avvio dell'applicazione
if __name__ == '__main__':
    db.connect()
    db.create_tables([User], safe=True)
    app.run(debug=True)
