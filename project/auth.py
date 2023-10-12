from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login' )
def login():
    return render_template("login.html")

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()
    

    # comprobar si el usuario realmente existe
    # tome la contraseña proporcionada por el usuario, haga un hash y compárela con la contraseña hash en la base de datos
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login_post')) # Si el usuario no existe o la contraseña es incorrecta, recarga la página.
    # Si se supera la verificación anterior, entonces sabemos que el usuario tiene las credenciales correctas.
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')


    user = User.query.filter_by(email=email).first() # Si esto devuelve un usuario, entonces el correo electrónico ya existe en la base de datos.

    if user: # Si se encuentra un usuario, queremos redireccionarlo a la página de registro para que el usuario pueda volver a intentarlo.
        flash('Email address already exists')
        return redirect(url_for('auth.signup_post'))

    # crear un nuevo usuario con los datos del formulario. Hash la contraseña para que no se guarde la versión de texto sin formato.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    # agregar el nuevo usuario a la base de datos
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))




