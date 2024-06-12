import datetime
import hashlib
import json
import sqlite3
from flask import Flask, make_response, render_template, request
from flask_cors import CORS
from flask_restx import Namespace, Resource, reqparse
from flask_jwt_extended import JWTManager, get_jwt, jwt_required, create_access_token
from flask_restx import Api

app = Flask(__name__)
CORS(app)  # Allow CO RS for all routes
#app.secret_key = 'supersecretkey'  # Required for flashing messages

app = Flask(__name__)
api = Api(app, version='1.0', title='MediTech BACKEND', description='Firmware Controller')

app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(seconds=28800)
app.config['PROPAGATE_EXCEPTIONS'] = True 
jwt = JWTManager(app)

authorizations = {
    'jsonWebToken': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

api2 = Namespace('Users', description='Users endpoint', authorizations=authorizations, security='jsonWebToken')
api.add_namespace(api2, path='/users')

# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/user_login')
# def user_login():
#     return render_template('login.html')

# @app.route('/appointments')
# def appointments():
#     return render_template('appointment.html')

# @app.route('/patient_data')
# def patient_data():
#     return render_template('patient.html')

# @app.route('/medical_records')
# def medical():
#     return render_template('medicalrecords.html')

@api2.route("/users/login")
class Login(Resource):
    def options(self):
            response = make_response(
                {'ok': True},
                200
            )
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "*")

            return response
    def post(self):
        data = request.get_json()
        
        if not all(key in data for key in ('user_email', 'user_password')):
            return {'error': 'All fields are required'}, 400
        
        email = data['user_email']
        password = data['user_password']
        
        m = hashlib.sha256()
        m.update(str.encode(password))

        password = m.hexdigest()

        if not email or not password:
            return {'error': 'All fields must be filled'}, 400

        conn = sqlite3.connect('C:\\Users\\Harry\\Desktop\\meditech\\backend\data\\meditech.db')
        c = conn.cursor()

        # Check if the email and password match
        c.execute('SELECT * FROM users WHERE user_email = ? AND user_password = ?', (email, password))
        existing_user = c.fetchone()

        if existing_user:
            conn.close()
            token = create_access_token(identity=email, additional_claims={'admin':existing_user[5]})

            response = make_response(
                {'ok': True, 'token': token},
                200
            )
            response.headers.add("Access-Control-Allow-Origin", "*")

            return response
                
        conn.close()
        response = make_response(
                {'ok': False, 'error': 'Incorrect username or password.'},
                400
        )
        response.headers.add("Access-Control-Allow-Origin", "*")


        return response 
@api2.route("/users/signup")
class Signup(Resource):
    def options(self):
            response = make_response(
                {'ok': True},
                200
            )
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "*")

            return response
    def post(self):
        data = request.get_json()
        
        # Validate input fields
        if not all(key in data for key in ('user_email', 'user_password')):
            response = make_response(
                {'error': 'All fields must be filled'}, 400
            )
            response.headers.add("Access-Control-Allow-Origin", "*")

            return response
        
        email = data['user_email']        
        password = data['user_password']
        
        m = hashlib.sha256()
        m.update(str.encode(password))

        password = m.hexdigest()

        if not email or not password:
            response = make_response(
                {'error': 'All fields must be filled'}, 400
            )
            response.headers.add("Access-Control-Allow-Origin", "*")

            return response

        conn = sqlite3.connect('C:\\Users\\Harry\\Desktop\\meditech\\backend\data\\meditech.db')
        c = conn.cursor()

        # Check if the email already exists
        c.execute('SELECT * FROM users WHERE user_email = ?', (email,))
        existing_user = c.fetchone()

        if existing_user:
            conn.close()
            response = make_response(
                {'error': 'Email already exists'}, 400
            )
            response.headers.add("Access-Control-Allow-Origin", "*")

            return response
        
        # Insert the new user if email does not exist
        c.execute('INSERT INTO users (user_email, user_password) VALUES (?, ?)', (email, password))
        conn.commit()
        conn.close()
        response = make_response(
                {'message': 'User added'},
                200
            )
        response.headers.add("Access-Control-Allow-Origin", "*")

        return response

@api2.route("/users/bookings")
class Bookings(Resource):
    def options(self):
            response = make_response(
                {'ok': True},
                200
            )
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add("Access-Control-Allow-Headers", "*")

            return response
    
    @jwt_required()
    #This works. It returns all the bookings related to the users email that is signed in, now all you have to do is making the booking page functional.

    def get(self):
        gotten_jwt = get_jwt()

        user_email = gotten_jwt.get("identity")

        conn = sqlite3.connect('C:\\Users\\Harry\\Desktop\\meditech\\backend\data\\meditech.db')
        c = conn.cursor()

        c.execute('SELECT * FROM bookings WHERE email = ?', (user_email,))

        gotten_bookings = c.fetchone()

        if gotten_bookings:
            response = make_response(
                {'bookings': gotten_bookings},
                200
            )

            response.headers.add("Access-Control-Allow-Origin", "*")

            return response

        response2 = make_response(
                    {'error': ''},
                    400
                )
        return response2

    @jwt_required()
    def post(self):
        data = request.get_json()

        gotten_jwt = get_jwt()

        user_email = gotten_jwt.get("identity")

        conn = sqlite3.connect('./data/meditech.db')
        c = conn.cursor()

        # Inserts the booking information

        c.execute('INSERT INTO bookings (name, address, condition, date, time, email) VALUES (?, ?)', (data["name"], data["address"], data["condition"], data["date"], data["time"], user_email))

        return {"ok": True}, 200

        # return response

@app.route('/bookings', methods=['GET', 'POST'])
def bookings():
    if request.method == 'POST':
        name = request.form['bookingName']
        address = request.form['bookingAddress']
        condition = request.form['bookingCondition']
        date = request.form['bookingDate']
        time = request.form['bookingTime']

        # Here you would typically save this data to a database
        # For now, we'll just flash a message
        # flash(f'Booking submitted for {name} on {date} at {time}', 'success')
        #return redirect(url_for('bookings'))
    return render_template('booking.html')


if __name__ == '__main__':
    app.run()