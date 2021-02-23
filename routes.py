from flask import jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from app import app
from app import db
from models import *

TOKEN_TIMEOUT = 30

# Check for token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            #print(token)

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            #print(data)
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Log in
@app.route('/login')
def login():
    auth = request.authorization
    #print(auth)

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()
    #print(user)

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_TIMEOUT)}, app.config['SECRET_KEY'], algorithm="HS256")
        #print(token)

        #return jsonify({'token' : token.decode('UTF-8')})
        return jsonify({'token' : token})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

# GET all users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})

  users = User.query.all()

  output = []

  for user in users:
    user_data = {}
    user_data['pulic_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    output.append(user_data)

  return jsonify({'users': output})

# GET user via public id
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})  

  users = User.query.all()

  user = User.query.filter_by(public_id=public_id).first()
  
  user_data = {}
  user_data['pulic_id'] = user.public_id
  user_data['name'] = user.name
  user_data['password'] = user.password
  user_data['admin'] = user.admin

  return jsonify({'users:', user_data})

# Create new user
@app.route('/user', methods=['POST'])
#@token_required
#def create_user(current_user):
def create_user():

  #if not current_user.admin:
  #  return jsonify({'message' : 'Cannot perform that function!'})  

  data = request.get_json()
  
  hashed_password = generate_password_hash(data['password'], method='sha256')
  admin = True if data['admin'] == "True" else False

  new_user = User(public_id = str(uuid.uuid4()), name = data['name'], password=hashed_password, admin=admin)
  db.session.add(new_user)
  db.session.commit()
  return jsonify({'message' : 'New user created!'})

# Promote existing user to admin via json
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user_json(current_user, public_id):

  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})

  data = request.get_json()
  public_id = data['public_id']
  user = User.query.filter_by(public_id=public_id).first()
  user.admin = True
  db.session.commit()
  return jsonify({'message' : 'New has been promoted!'})

# Edit existing user
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
  
  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})

  user = User.query.filter_by(public_id=public_id).first()
  user.admin = True
  db.session.commit()
  return jsonify({'message' : 'The user has been promoted!'})

# Delete existing user vis json
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user_json(current_user, public_id):

  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})

  data = request.get_json()
  public_id = data['public_id']
  user = User.query.filter_by(public_id=public_id).first()
  db.session.delete(user)
  db.session.commit()
  return jsonify({'message' : 'New has been deleted!'})

# Delete existing user
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

  if not current_user.admin:
    return jsonify({'message' : 'Cannot perform that function!'})

  user = User.query.filter_by(public_id=public_id).first()
  db.session.delete(user)
  db.session.commit()
  return jsonify({'message' : 'The user has been deleted!'})

# Get all books
@app.route('/books', methods=['GET'])
@token_required
def gBooks(current_user):
  allBooks = Books.query.all()
  output = []
  for book in allBooks:
    currBook = {}
    currBook['bookTitle'] = book.bookTitle
    currBook['bookText'] = book.bookText
    currBook['likes'] = book.likes
    output.append(currBook)
  return jsonify(output)  

# Add a new book
@app.route('/books', methods=['POST'])
@token_required
def pBooks(current_user):
  bookData = request.get_json()
  book = Books(bookTitle = bookData['bookTitle'], bookText = bookData['bookText'], likes = bookData['likes'])
  db.session.add(book)
  db.session.commit()
  return jsonify(bookData) 

# Update an existing book as liked
@app.route('/books/<bookTitle>', methods=['PUT'])
@token_required
def updateLikes(current_user, bookTitle):
  bookData = request.get_json()
  currBook = bookData['bookTitle']
  book = Books.query.filter_by(bookTitle=currBook).first()
  book.likes = 1
  db.session.commit()
  return jsonify(bookData) 

# Search for a book via title
@app.route('/books/<bookTitle>', methods=['GET'])
@token_required
def search(current_user, bookTitle):
  allBooks = Books.query.filter(books.bookTitle.contains(bookTitle)).order_by(books.bookTitle)
  output = []
  for book in allBooks:
    currBook = {}
    currBook['bookTitle'] = book.bookTitle
    currBook['bookText'] = book.bookText
    currBook['likes'] = book.likes
    output.append(currBook)
  return jsonify(output)

# Delete a book
@app.route('/books/<bookTitle>', methods=['DELETE'])
@token_required
def deleteBook(current_user, bookTitle):
  book = Books.query.filter_by(bookTitle=bookTitle).first()
  db.session.delete(book)
  db.session.commit()
  return jsonify({'message':'The user has been deleted'}) 

# Delete a book via json
@app.route('/books/<bookTitle>', methods=['DELETE'])
@token_required
def deleteBookJson(current_user, bookTitle):
  bookData = request.get_json()
  currBook = bookData['bookTitle']
  book = Books.query.filter_by(bookTitle=currBook).first()
  db.session.delete(book)
  db.session.commit()
  return jsonify(bookData)    