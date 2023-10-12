from flask import Blueprint, render_template
from project import db
from flask_login import login_required, current_user

from project import create_app

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)



app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=8080
            )
    
  
