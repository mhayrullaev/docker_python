from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecretkey'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:mysecretpassword@10.250.8.232/mhdev'
app.debug = True
db = SQLAlchemy(app)

from models import *

db.create_all()
db.session.commit()

from routes import *

if __name__ == '__main__':
  #app.run()
  app.run(host='0.0.0.0', port=5000)