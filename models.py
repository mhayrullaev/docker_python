from app import db

class Books(db.Model):
  __tablename__ = 'books'
  bookTitle = db.Column(db.String(100), primary_key=True)
  bookText = db.Column(db.String(), nullable=False)
  likes = db.Column(db.Integer, nullable=False, default=0)

  def __init__(self, bookTitle, bookText, likes):
    self.bookTitle = bookTitle
    self.bookText = bookText
    self.likes = likes

class User(db.Model):
  __tablename__ = 'users'
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.String(50), unique=True)  
  name = db.Column(db.String(50), nullable=False)
  password = db.Column(db.String(80), nullable=False)
  admin = db.Column(db.Boolean)

  def __init__(self, public_id, name, password, admin):
    self.public_id = public_id
    self.name = name
    self.password = password
    self.admin = admin  