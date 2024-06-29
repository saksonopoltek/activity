# Importing libraries
from flask import Flask, request, jsonify, session, render_template
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from datetime import timedelta, datetime
from flask_cors import CORS
import pymysql
from itsdangerous import SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
# Configuration of mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '19098001.sumantri@student.poltektegal.ac.id'
app.config['MAIL_PASSWORD'] = 'nwkfbrygihpvsfcs'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['SECRET_KEY'] = 'tracking'
mail = Mail(app)


app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Set expiration time to 1 hour
app.config['JWT_SECRET_KEY'] = 'poltekdaily'
jwt = JWTManager(app)

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'db': 'dailyku'
}
# Global set to store active access tokens
access_token_set = set()

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
            sql = "SELECT password FROM users WHERE username = %s"
            cursor.execute(sql, (username,))
            result = cursor.fetchone()
            
            if result:
                stored_password_hash = result[0]
                return check_password_hash(stored_password_hash, password)
            else:
                return False
    finally:
        connection.close()



# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if validate_login(username, password):
        user_id = get_user_id_by_username(username)
        new_access_token = create_access_token(identity=user_id)
        access_token_set.add(new_access_token)  # Add the token to the global set
        print(f"Current access_token_set (login): {access_token_set}")
        return jsonify({'access_token_set': new_access_token, 'user_id': user_id, 'username': username, 'message': 'Login successful', 'isLogged': True})
    else:
        return jsonify({'message': 'Invalid username or password', 'isLogged': False}), 401

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    # Extract the token from the request data
    data = request.json
    token_to_revoke = data.get('token')
    # Print the entire request data for debugging
    print(f"Received token in logout route: {request.data}")

    # Check if the token is in the active_tokens set
    if token_to_revoke and token_to_revoke in access_token_set:
        # Remove the token from the active_tokens set
        access_token_set.remove(token_to_revoke)
        return jsonify({'message': 'Logout successful'}), 200
    else:
        return jsonify({'message': 'Invalid token or user not logged in'}), 401




    
@app.route('/get_current_user_id', methods=['GET'])
def get_current_user_id():
    if 'user_id' in session:
        user_id = session['user_id']
        app.logger.info(f'User ID retrieved: {user_id}')  # Log the user ID
        return jsonify({'user_id': user_id}), 200
    else:
        app.logger.warning('User not logged in')  # Log a warning
        return jsonify({'message': 'User not logged in'}, 401)


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

# register route
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Check if email is already registered
    if is_email_registered(email):
        return jsonify({'message': 'Email is already registered'}), 400

    # Check if username is already registered
    if is_username_registered(username):
        return jsonify({'message': 'Username is already registered'}), 400

    # Hash the password before storing
    hashed_password = generate_password_hash(password)

    # Store the user
    store_user(username, hashed_password, email)

    # Send the registration email
    send_registration_email(email)

    response_data = {'message': 'Registration successful', 'isRegistered': True}
    return jsonify(response_data)


#send mail thank you for registering
def send_registration_email(recipient):
    try:
        subject = "Thank You for Registering"
        sender_email = "19098001.sumantri@student.poltektegal.ac.id"
        
        # Customize your thank you message
        body = "Thank you for registering with us! We appreciate your participation."

        msg = Message(subject, sender=sender_email, recipients=[recipient])
        msg.body = body
        mail.send(msg)

        app.logger.info(f"Registration email sent successfully to {recipient}")
    except Exception as e:
        app.logger.error(f"Error sending registration email to {recipient}: {str(e)}")

#generate reset token
@app.route('/generate-reset-token', methods=['POST'])
def generate_reset_token():
    data = request.json
    email = data.get('email')
    username = data.get('username')

    # Check if the username and email match
    if not is_user_matched(username, email):
        return jsonify({'message': 'Invalid username or email'}), 401

    # Generate a JWT token with the email included in the payload
    reset_token_payload = {'email': email}
    reset_token = create_access_token(identity=username, additional_claims=reset_token_payload, expires_delta=False)

    # Log the generated token for debugging
    app.logger.info(f"Generated Reset Token: {reset_token}")

    # Send the reset token to the user's email
    send_reset_email(username, email, reset_token)

    return jsonify({'message': 'Reset token generated and sent successfully'}), 200



def get_username_for_reset(request_data):
    # Assuming the username is in the JSON data
    username = request_data.get('username', None)

    if username is None:
        # Handle the case when the username is not found in the request data
        # You can raise an exception, return a default value, or handle it in any way you prefer
        return 'default_username'
    
    return username

#send reset mail
def send_reset_email(username, recipient, reset_token):
    try:
        subject = "Password Reset"
        sender_email = "19098001.sumantri@student.poltektegal.ac.id"
        reset_link = f"http://192.168.48.172:5000/reset-password?token={reset_token}"

        body = f"Hello {username},\n\nClick the following link to reset your password: {reset_link}"

        msg = Message(subject, sender=sender_email, recipients=[recipient])
        msg.body = body
        mail.send(msg)

        app.logger.info(f"Reset email sent successfully to {recipient}")
    except Exception as e:
        app.logger.error(f"Error sending reset email to {recipient}: {str(e)}")


# Reset password form route
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    app.logger.info("Reset password route called.")
    
    if request.method == 'POST':
        app.logger.info("POST request received.")
        data = request.get_json()
        token = data.get('reset_token')
        new_password = data.get('new_password')
        
        if not token:
            app.logger.error("Token is missing.")
            return jsonify({'message': 'Token is missing.'}), 400
        
        app.logger.info(f"Token received: {token}")

        try:
            payload = decode_token(token)
            email = payload.get('email')

            if not email:
                app.logger.error("Token does not contain email information.")
                return jsonify({'message': 'Token does not contain email information.'}), 400

            app.logger.info(f"Token is valid. Email extracted: {email}")

            if not new_password:
                app.logger.error("Missing new password.")
                return jsonify({'message': 'Missing new password.'}), 400

            update_password(email, new_password)
            app.logger.info("Password reset successful.")
            return jsonify({'message': 'Password reset successful.', 'success': True})
        except SignatureExpired:
            app.logger.error("Token expired.")
            return jsonify({'message': 'Token expired. Please generate a new reset token.'}), 400
        except BadSignature:
            app.logger.error("Invalid token.")
            return jsonify({'message': 'Invalid token. Please generate a new reset token.'}), 400

    else:
        app.logger.info("GET request received.")
        token = request.args.get('token')
        if not token:
            app.logger.error("Token is missing.")
            return 'Token is missing.', 400

        try:
            payload = decode_token(token)
            email = payload.get('email')
            if not email:
                app.logger.error("Token does not contain email information.")
                return 'Token does not contain email information.', 400
            return render_template('reset_password_form.html', token=token)
        except SignatureExpired:
            app.logger.error("Token expired.")
            return 'Token expired. Please generate a new reset token.', 400
        except BadSignature:
            app.logger.error("Invalid token.")
            return 'Invalid token. Please generate a new reset token.', 400

@app.route('/success')
def reset_success():
    return render_template('success.html')


def update_password(email, new_password):
    hashed_password = generate_password_hash(new_password)
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "UPDATE users SET password = %s WHERE email = %s"
            cursor.execute(sql, (hashed_password, email))
            connection.commit()
    finally:
        connection.close()




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

@app.route('/get_user_info', methods=['GET'])
def get_user_info():
    if 'user_id' in session:
        user_id = session['user_id']
        user_info = get_user_info_from_database(user_id)
        return jsonify(user_info)
    else:
        return jsonify({'error': 'User not logged in'}), 401

def get_user_info_from_database(user_id):
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT username, email FROM users WHERE id = %s"
            cursor.execute(sql, (user_id,))
            result = cursor.fetchone()

            if result and len(result) >= 2:  # Check if result is not None and has at least 2 elements
                user_info = {'username': result[0], 'email': result[1]}
                return user_info
            else:
                return {'error': 'User not found or incomplete data'}
    finally:
        connection.close()

#save steps data
@app.route('/save_steps', methods=['POST'])
def save_steps():
    try:
        data = request.get_json()
        steps = data['steps']
        user_id = data['user_id']  # Make sure to include 'user_id' in the JSON data

        print(f"Received steps: {steps}, user_id: {user_id}")
        # Get the current date and time
        current_date_time = datetime.utcnow().strftime('%Y-%m-%d')

        with pymysql.connect(**db_config) as conn:
            with conn.cursor() as cursor:
                # Assuming your step_data table has 'user_id', 'steps', and 'timestamp' columns
                cursor.execute("INSERT INTO steps_data (user_id, steps, date) VALUES (%s, %s, %s)", (user_id, steps, current_date_time))
                conn.commit()

        return jsonify({'message': 'Steps saved successfully'}), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500


# Replace this with your actual logic to retrieve steps data from the MySQL database
def get_steps_data(user_id):
    connection = None
    try:
        connection = pymysql.connect(**db_config)
        cursor = connection.cursor()

        # Modify the SQL query to fetch steps data based on user ID
        cursor.execute("SELECT date, steps FROM steps_data WHERE user_id = %s ORDER BY date DESC", (user_id,))
        steps_data = cursor.fetchall()  # fetch all entries

        # Format the data as a list of dictionaries
        formatted_steps_data = [
            {'date': row[0].strftime('%Y-%m-%d'), 'steps': row[1]} for row in steps_data
        ]

        return formatted_steps_data
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection and connection.open:
            connection.close()

@app.route('/read_steps_data/<int:user_id>', methods=['GET'])
def read_steps_data_route(user_id):
    try:
        steps_data = get_steps_data(user_id)

        if steps_data:
            # Print the response before sending it
            print(f"Steps Data Response: {steps_data}")
            return jsonify(steps_data)
        else:
            return jsonify({'error': 'No steps data available for the specified user'})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': f'Unable to fetch steps data for user {user_id}'})


#save fasting
@app.route('/save_fasting', methods=['POST'])
def save_fasting():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        hours = data.get('hours')
        date = data.get('date')  # Get the date from the request
        
        print(f"Received fast: {hours}, user_id: {user_id}, date: {date}")
        
        # Connect to the database and save data
        with pymysql.connect(**db_config) as conn:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO fast_data (user_id, hours, date) VALUES (%s, %s, %s)", (user_id, hours, date))
                conn.commit()

        return jsonify({'message': 'Fast Data saved successfully'}), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500

    
def get_fast_data(user_id):
    connection = None
    try:
        connection = pymysql.connect(**db_config)
        cursor = connection.cursor()

        # Modify the SQL query to fetch fast data based on user ID
        cursor.execute("SELECT date, hours FROM fast_data WHERE user_id = %s ORDER BY date DESC", (user_id,))
        fast_data = cursor.fetchall()  # fetch all entries

        # Format the data as a list of dictionaries
        formatted_fast_data = [{'date': row[0], 'hours': row[1]} for row in fast_data]

        return formatted_fast_data
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection and connection.open:
            connection.close()


@app.route('/read_fast_data/<int:user_id>', methods=['GET'])
def read_fast_data_route(user_id):
    try:
        fast_data = get_fast_data(user_id)

        if fast_data:
            # Print the response before sending it
            print(f"Fast Data Response: {fast_data}")
            return jsonify(fast_data)
        else:
            return jsonify({'error': 'No fast data available for the specified user'})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': f'Unable to fetch fast data for user {user_id}'})


#save intake water
@app.route('/add_intake', methods=['POST'])
def add_intake():
    try:
        data = request.get_json()

        # Ensure 'user_id' key is present in the JSON data
        if 'user_id' not in data:
            return jsonify({'error': 'Missing user_id in input data'}), 400

        # Validate input data
        user_id = data['user_id']
        date = data['date']  # Changed from 'dateTime' to 'date'
        amount = data['amount']

        if not all([user_id, date, amount]):
            return jsonify({'error': 'Invalid input data'}), 400

        # Parse date string into a Python date object
        date_obj = datetime.strptime(date, '%Y-%m-%d').date()  # Assuming date format is 'YYYY-MM-DD'

        # Use a context manager to connect to the MySQL database
        with pymysql.connect(**db_config) as conn:
            try:
                # Begin a transaction
                conn.begin()

                with conn.cursor() as cursor:
                    # Insert the data into the MySQL database
                    insert_query = "INSERT INTO water_intake (user_id, date, amount) VALUES (%s, %s, %s)"  # Changed from 'dateTime' to 'date'
                    data = (user_id, date_obj, amount)  # Changed 'datetime_obj' to 'date_obj'
                    cursor.execute(insert_query, data)

                # Commit the transaction
                conn.commit()
                # Prepare the response data
                response_data = {
                    'user_id': user_id,
                    'date': date,  # Changed from 'dateTime' to 'date'
                    'amount': amount,
                    'message': 'Water intake record added successfully'
                }

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
    

def get_water_data(user_id):
    connection = None
    try:
        connection = pymysql.connect(**db_config)
        cursor = connection.cursor()

        # Modify the SQL query to fetch water data based on user ID
        cursor.execute("SELECT date, amount FROM water_intake WHERE user_id = %s ORDER BY date DESC", (user_id,))
        water_intake = cursor.fetchall()  # fetch all entries

        # Group water data by day and sum the intake liters for each day
        water_intake_by_day = {}
        for date, amount in water_intake:
            if date not in water_intake_by_day:
                water_intake_by_day[date] = 0
            water_intake_by_day[date] += amount

        # Format the aggregated data as a list of dictionaries
        formatted_water_data = [{'date': date, 'amount': amount} for date, amount in water_intake_by_day.items()]

        return formatted_water_data
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        if connection and connection.open:
            connection.close()


@app.route('/read_water_data/<int:user_id>', methods=['GET'])
def read_water_data_route(user_id):
    try:
        water_intake = get_water_data(user_id)

        if water_intake:
            # Print the response before sending it
            print(f"Water Data Response: {water_intake}")
            return jsonify(water_intake)
        else:
            return jsonify({'error': 'No water data available for the specified user'})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': f'Unable to fetch water data for user {user_id}'})



if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
