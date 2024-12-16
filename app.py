from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
import random
from functools import wraps
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import os
import sqlite3

# Load the .env file
load_dotenv()

# Retrieve the encryption key from the .env file
encryption_key = os.getenv('ENCRYPTION_KEY')

# Create Fernet instance for encryption/decryption
if encryption_key:
    fernet = Fernet(encryption_key.encode())
else:
    raise ValueError("ENCRYPTION_KEY not set in .env file!")

# Flask setup
app = Flask(__name__)
app.secret_key = 'zW1bY2NnV2pLbHNtT3FtRFBzUXZVYjloSWdPVE1GeEE='

# IP blocking setup
BLOCKED_IPS = {''}  # 127.0.0.1


def check_ip(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        print(f"[DEBUG] Incoming request from IP: {request.remote_addr}")
        if request.remote_addr in BLOCKED_IPS:
            print(f"[DEBUG] Blocked IP: {request.remote_addr}")
            return jsonify({'error': 'blocked'}), 403
        return f(*args, **kwargs)
    return wrapper

# Database setup
conn = sqlite3.connect('footballers.db', check_same_thread=False)
cursor = conn.cursor()

# Create tables
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        encrypted_password TEXT NOT NULL
    )
''')
conn.commit()
print("[DEBUG] Users table ensured in the database.")

# Encryption/Decryption Functions
def encrypt_data(data: str) -> str:
    print(f"[DEBUG] Encrypting data: {data}")
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    print(f"[DEBUG] Decrypting data: {encrypted_data}")
    return fernet.decrypt(encrypted_data.encode()).decode()

@app.route('/debug_decrypt')
def debug_decrypt():
    cursor.execute("SELECT username, encrypted_password FROM users")
    users = cursor.fetchall()
    print(f"[DEBUG] Retrieved users: {users}")
    decrypted_users = [
        {"username": user[0], "decrypted_password": decrypt_data(user[1])}
        for user in users
    ]
    return jsonify(decrypted_users)

# Routes for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"[DEBUG] Registering user: {username}")

        try:
            encrypted_password = encrypt_data(password)
            cursor.execute("INSERT INTO users (username, encrypted_password) VALUES (?, ?)",
                           (username, encrypted_password))
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            print(f"[DEBUG] Registration failed: {e}")
            flash("Username already exists. Try another one.", "danger")

    return render_template('register.html')

# Routes for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"[DEBUG] Login attempt for user: {username}")

        cursor.execute("SELECT encrypted_password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        print(f"[DEBUG] Retrieved user: {user}")

        if user and decrypt_data(user[0]) == password:
            session['username'] = username
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials. Please try again.", "danger")

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    print(f"[DEBUG] Logging out user: {session.get('username')}")
    session.pop('username', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# function to get a random word
FOOTBALLERS_FILE = "static/list_of_footballers"

def get_random_word():
    try:
        with open(FOOTBALLERS_FILE, 'r') as f:
            words = f.readlines()
        random_word = random.choice(words).strip().lower()
        print(f"[DEBUG] Random word selected: {random_word}")
        return random_word
    except Exception as e:
        print(f"[DEBUG] Error reading footballers file: {e}")
        return "unknown"

# Route for starting a new game
@app.route('/new_game', methods=['POST'])
@check_ip
def new_game():
    if 'username' not in session:
        return redirect(url_for('login'))

    session['nameToGuess'] = get_random_word()
    session['lettersSet'] = 'abcdefghijklmnopqrstuvwxyz'
    session['toDisplay'] = ['_' if char != ' ' else ' ' for char in session['nameToGuess']]
    session['blanks'] = session['toDisplay'].count('_')
    session['tries'] = 0
    session['hintsUsed'] = 0  # Initialize hints used

    print(f"[DEBUG] New game initialized: {session['nameToGuess']}")
    flash("New game started!", "info")
    return redirect(url_for('play'))

# Route for the game page
@app.route('/play')
@check_ip
def play():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'nameToGuess' not in session:
        return redirect(url_for('index'))

    display_word = ' '.join(session['toDisplay'])
    game_won = session['blanks'] == 0
    game_over = session['tries'] >= 6

    hangman_image = f"images/hangman{session['tries']}.jpg"
    print(f"[DEBUG] Current game state: {display_word}, Tries: {session['tries']}, Game Over: {game_over}")

    return render_template(
        'play.html',
        display_word=display_word,
        lettersSet=session['lettersSet'],
        tries=hangman_image,
        game_won=game_won,
        game_over=game_over,
        nameToGuess=session['nameToGuess'] if game_over else None
    )

# Route for hints
@app.route('/hint', methods=['POST'])
@check_ip
def hint():
    if 'username' not in session or 'nameToGuess' not in session:
        return redirect(url_for('login'))

    if 'hintsUsed' not in session:
        session['hintsUsed'] = 0

    if session['hintsUsed'] >= 2:
        flash("You have already used all your hints!", "warning")
    else:
        name_to_guess = session['nameToGuess']
        to_display = session['toDisplay']

        hidden_indices = [i for i, char in enumerate(name_to_guess) if to_display[i] == '_']
        if hidden_indices:
            random_index = random.choice(hidden_indices)
            to_display[random_index] = name_to_guess[random_index]
            session['toDisplay'] = to_display
            session['blanks'] -= 1
            session['hintsUsed'] += 1
            flash("Hint used! A letter has been revealed.", "info")
        else:
            flash("No more letters to reveal!", "info")

    return redirect(url_for('play'))

# Route to handle guesses
@app.route('/guess', methods=['POST'])
@check_ip
def guess():
    guess = request.form.get('letter', '').lower()
    print(f"[DEBUG] Guess received: {guess}")

    if guess and guess.isalpha() and len(guess) == 1:
        chance_lost = True
        for i, char in enumerate(session['nameToGuess']):
            if char == guess:
                chance_lost = False
                session['toDisplay'][i] = guess
                session['blanks'] -= 1

        session['lettersSet'] = session['lettersSet'].replace(guess, '')

        if chance_lost:
            session['tries'] += 1

        print(f"[DEBUG] Updated game state: {session['toDisplay']}, Tries: {session['tries']}")
        return redirect(url_for('play'))

    flash("Invalid guess. Try again.", "danger")
    return redirect(url_for('play'))

# index route to check login
@app.route('/')
@check_ip
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    print(f"[DEBUG] Index accessed by user: {session['username']}")
    return render_template('index.html', username=session['username'])

if __name__ == '__main__':
    app.run(debug=True)
