# Importing libraries
import random
from flask import Flask, request, jsonify, session
from flask_mail import Mail, Message
from flask_session import Session
from datetime import timedelta, datetime
from flask_cors import CORS, cross_origin
import pymysql
import string


app = Flask(__name__)
app.secret_key = 'DE5B3C3A59789A6CF911BD35'

# Configuration of mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '19098001.sumantri@student.poltektegal.ac.id'
app.config['MAIL_PASSWORD'] = 'nwkfbrygihpvsfcs'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# Configure the session to use MySQL
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_USE_SIGNER'] = True  # For added security (optional)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Session lifetime
Session(app)

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'db': 'dailyku'
}

CORS(app)


@app.route('/')
def hello():
    return "hello"

# Check if an email is already registered
def is_email_registered(email):
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE email = %s"
            cursor.execute(sql, (email,))
            result = cursor.fetchone()
            return result is not None
    finally:
        connection.close()

# Check if a username is already registered
def is_username_registered(username):
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username = %s"
            cursor.execute(sql, (username,))
            result = cursor.fetchone()
            return result is not None
    finally:
        connection.close()

# Store registered users in a MySQL database
def store_user(username, password, email):
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)"
            cursor.execute(sql, (username, password, email))
        connection.commit()
    finally:
        connection.close()


# Validate login credentials against the database
def validate_login(username, password):
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username = %s AND password = %s"
            cursor.execute(sql, (username, password))
            result = cursor.fetchone()
            return result is not None
    finally:
        connection.close()


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    app.logger.debug(f"Received login request for username: {username}")

    if validate_login(username, password):
        user_id = get_user_id_by_username(username)
        
        # Store both user_id and username in the session
        session['user_id'] = user_id
        session['username'] = username

        app.logger.info(f"Login successful for username: {username}, user_id: {user_id}")

        return jsonify({'message': 'Login successful', 'user_id': user_id})
    else:
        app.logger.warning(f"Login failed for username: {username}")
        return 'Invalid username or password', 401

    
@app.route('/check_session', methods=['GET'])
@cross_origin(origin='*')
def check_session():
    if 'user_id' in session:
        user_id = session['user_id']
        app.logger.info(f"User with ID {user_id} is logged in")  # Log user login
        return jsonify({'user_id': user_id}), 200
    else:
        app.logger.info("User not logged in")  # Log user not logged in
        return jsonify({'message': 'User not logged in'}, 401)
    
@app.route('/get_current_user_id', methods=['GET'])
def get_current_user_id():
    if 'user_id' in session:
        user_id = session['user_id']
        app.logger.info(f'User ID retrieved: {user_id}')  # Log the user ID
        return jsonify({'user_id': user_id}), 200
    else:
        app.logger.warning('User not logged in')  # Log a warning
        return jsonify({'message': 'User not logged in'}, 401)



@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user_id', None)  # Remove the user ID from the session
    return 'Logged out successfully'

def get_user_id_by_username(username):
    # Connect to your MySQL database
    connection = pymysql.connect(**db_config)

    try:
        with connection.cursor() as cursor:
            # Define a SQL query to fetch the user_id based on the provided username
            sql = "SELECT id FROM users WHERE username = %s"
            cursor.execute(sql, (username,))

            # Fetch the result of the query (the user_id)
            result = cursor.fetchone()

            if result:
                user_id = result[0]  # Assuming the ID is in the first column
                return user_id
            else:
                return None  # Username not found, return None or raise an exception
    finally:
        connection.close()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Check if email is already registered
    if is_email_registered(email):
        return 'Email is already registered'

    # Check if username is already registered
    if is_username_registered(username):
        return 'Username is already registered'

    store_user(username, password, email)  # Update store_user function

    response_data = {'message': 'Registration successful'}
    return jsonify(response_data)


#define match user between username and email 
def is_user_matched(username, email):
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username = %s AND email = %s"
            cursor.execute(sql, (username, email))
            result = cursor.fetchone()
            return result is not None
    finally:
        connection.close()

@app.route('/generate-random-password', methods=['POST'])
def generate_random_password():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')

        if not username or not email:
            return jsonify({"error": "Invalid username or email"}), 400

        # Check if the provided username and email match an existing user
        if not is_user_matched(username, email):
            return jsonify({"error": "Username and email do not match an existing user"}), 400

        # Generate a random password
        password_length = 10
        random_password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(password_length))

        # Update the user's password in the database
        update_user_password(email, random_password)

        # Send the password to the provided email
        send_email(email, random_password)

        return jsonify({"newPassword": random_password})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def update_user_password(email, new_password):
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "UPDATE users SET password = %s WHERE email = %s"
            cursor.execute(sql, (new_password, email))
        connection.commit()
    finally:
        connection.close()


def send_email(recipient, password):
    msg = Message("Reset Password", sender="19098001.sumantri@student.poltektegal.ac.id", recipients=[recipient])
    msg.body = f"Your new password is: {password}"
    mail.send(msg)



@app.route('/add_intake', methods=['POST'])
def add_intake():
    try:
        data = request.get_json()

        # Validate input data
        user_id = data("user_id")
        dateTime = data("dateTime")
        amount = data("amount")

        if not all([user_id, dateTime, amount]):
            return jsonify({'error': 'Invalid input data'}), 400

        # Parse dateTime string into a Python datetime object
        datetime_obj = datetime.strptime(dateTime, '%H:%M')

        # Use a context manager to connect to the MySQL database
        with pymysql.connect(**db_config) as conn:
            try:
                # Begin a transaction
                conn.begin()

                with conn.cursor() as cursor:
                    # Insert the data into the MySQL database
                    insert_query = "INSERT INTO water_intake (user_id, dateTime, amount) VALUES (%s, %s, %s)"
                    data = (user_id, datetime_obj, amount)
                    cursor.execute(insert_query, data)

                # Commit the transaction
                conn.commit()
                # Prepare the response data
                response_data = {
                    'user_id': user_id,
                    'dateTime': dateTime,
                    'amount': amount,
                    'message': 'Water intake record added successfully'
                }

                # Return the response data
                return jsonify(response_data), 200
                # Return a success message
                return jsonify({'message': 'Water intake record added successfully'}), 200
            except pymysql.Error as e:
                # Rollback the transaction in case of an error
                conn.rollback()
                error_message = f"MySQL Error: {str(e)}"
                app.logger.error(error_message)
                return jsonify({'error': error_message}), 500
    except Exception as e:
        # Handle other exceptions
        error_message = f"An error occurred: {str(e)}"
        app.logger.error(error_message)
        return jsonify({'error': error_message}), 500


@app.route('/save_steps', methods=['POST'])
def save_steps():
    try:
        data = request.get_json()
        steps = data['steps']
        user_id = data['user_id']  # Make sure to include 'user_id' in the JSON data

        with pymysql.connect(**db_config) as conn:
            with conn.cursor() as cursor:
                # Assuming your step_data table has a 'user_id' column
                cursor.execute("INSERT INTO steps_data (user_id, steps) VALUES (%s, %s)", (user_id, steps))
                conn.commit()

        return jsonify({'message': 'Steps saved successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/save_fasting', methods=['POST'])
def save_fasting():
    try:
        data = request.get_json()
        amount = data['amount']
        user_id = data['user_id']  # Make sure to include 'user_id' in the JSON data

        with pymysql.connect(**db_config) as conn:
            with conn.cursor() as cursor:
                # Assuming your step_data table has a 'user_id' column
                cursor.execute("INSERT INTO fast_data (user_id, amount) VALUES (%s, %s)", (user_id, amount))
                conn.commit()

        return jsonify({'message': 'Steps saved successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
