from flask import Flask, render_template, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import requests
from flask import request

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Constants
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
month_mapper = {
    247: 1,
    249: 3,
    251: 5,
    253: 7,
    255: 9,
    257: 11
}
BASE_URL = "https://api-dbw.stat.gov.pl/api/1.1.0/variable/variable-data-section"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Nazwa użytkownika"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField('Zarejestruj')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'Taki użytkownik istnieje. Wybierz inną nazwę')


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Nazwa użytkownika"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField('Zaloguj')


class ApiClient(FlaskForm):
    def __getData(from_year, to_year, id_variable, id_part):
        test_periods = []

        periods_codes = [247, 249, 251, 253, 255, 257]
        for years in range(from_year, to_year+1):
            for i, periods in enumerate(periods_codes):
                URL = '{0}?id-zmienna={1}&id-przekroj={2}&id-rok={3}&id-okres={4}&ile-na-stronie=50&numer-strony=0&lang=pl'.format(BASE_URL, str(id_variable), str(id_part), str(years), str(periods))

                string_json = requests.get(URL)

                json = string_json.json()
                response_data = json['data']
                # To calculate average
                data_records = 0
                final_result = 0
                # check records
                for record in response_data:
                    final_result = final_result + record["wartosc"]
                    year = record["id-daty"]
                    period = record["id-okres"]
                    if record["wartosc"] != 0:
                        data_records += 1

                # append data
                test_periods.append({'date': str(month_mapper[period]) + "." + str(year), 'average_value': round(final_result / data_records)})
        return test_periods

    def getNewRegistered(from_y, to_y):
        data_of_new_registered_unemployed = ApiClient.__getData(from_y, to_y, 505, 16)
        new_registered_label = []
        new_registered_values = []
        for rec in data_of_new_registered_unemployed:
            new_registered_label.append(rec["date"])
            new_registered_values.append(rec["average_value"])
        return new_registered_label, new_registered_values
    def getNewUnregistered(from_y, to_y):
        data_of_new_unregistered_unemployed = ApiClient.__getData(from_y, to_y, 506, 16)
        new_unregistered_label = []
        new_unregistered_values = []
        for rec in data_of_new_unregistered_unemployed:
            new_unregistered_label.append(rec["date"])
            new_unregistered_values.append(rec["average_value"])
        return new_unregistered_label, new_unregistered_values
    def getRegistered(from_y, to_y):
        data_of_registered_unemployed = ApiClient.__getData(from_y, to_y, 507, 16)
        registered_label = []
        registered_values = []
        for rec in data_of_registered_unemployed:
            registered_label.append(rec["date"])
            registered_values.append(rec["average_value"])
        return registered_label, registered_values
    def getGeneralSituation(from_y, to_y):
        data_of_general_situation = ApiClient.__getData(int(from_y), int(to_y), 477, 16)
        general_situation_label = []
        general_situation_values = []
        for rec in data_of_general_situation:
            general_situation_label.append(rec["date"])
            general_situation_values.append(rec["average_value"])
        return general_situation_label, general_situation_values

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/home', methods =["GET", "POST"])
@login_required
def home():
    if request.method == "POST":
        from_y = request.form['from_year']
        to_y = request.form['to_year']
    else:
        from_y = 2019
        to_y = 2021
    user = current_user.username

    # bezrobotni nowo zarejestrowani
    new_registered_label, new_registered_values = ApiClient.getNewRegistered(int(from_y), int(to_y))

    # bezrobotni wyrejestrowani
    new_unregistered_label, new_unregistered_values = ApiClient.getNewUnregistered(int(from_y), int(to_y))

    # bezrobotni zarejestrowani
    registered_label, registered_values = ApiClient.getRegistered(int(from_y), int(to_y))

    # zmiana ogólnej sytuacji gospodarczej
    general_situation_label, general_situation_values = ApiClient.getGeneralSituation(int(from_y), int(to_y))

    return render_template('home.html',
                           new_registered_label=new_registered_label,
                           new_registered_values=new_registered_values,
                           new_unregistered_label=new_unregistered_label,
                           new_unregistered_values=new_unregistered_values,
                           registered_label=registered_label,
                           registered_values=registered_values,
                           general_situation_values=general_situation_values,
                           general_situation_label=general_situation_label,
                           user=user)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
