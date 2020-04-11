from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt, uuid, datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'root'
app.config['SQLALCHEMY_DATABASE_URI'] = 'C:/Users/Maharshi/Documents/api_example/todo.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    publicId = db.Column(db.String(255), unique=True)
    name = db.Column(db.String(255))
    password = db.Column(db.String(255))
    admin = db.Column(db.Boolean)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    amazonURL = db.Column(db.String(255))
    author = db.Column(db.String(255))
    generalInfo = db.Column(db.String(255))
    userId = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

# token
def TokenRequired(function):
    @wraps(function)
    def Decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return (jsonify({'message' : 'Token is required'}), 401)
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            currentUser = User.query.filter_by(publicId = data['publicId']).first()
        except:
            return jsonify({'message' : 'Token is invalid'})
        
        return function(currentUser, *args, **kwargs)

    return Decorated


@app.route('/user', methods=['GET'])
@TokenRequired
def GetAllUser(currentUser):
    if not currentUser.admin:
        return jsonify({'message' : 'You have not access to perform this operation'})
    
    users = User.query.all()
    
    result = []
    for user in users:
        userData = {}
        userData['publicId'] = user.publicId
        userData['name'] = user.name
        userData['password'] = user.password
        userData['admin'] = user.admin
        result.append(userData)
    
    return jsonify({'users :' : result})

@app.route('/user/<publicId>', methods=['GET'])
@TokenRequired
def GetOneUser(currentUser, publicId):
    if not currentUser.admin:
        return jsonify({'message' : 'You have not access to perform this operation'})
    
    user = User.query.filter_by(publicId = publicId).first()

    if not user:
        return jsonify({'message' : 'User Not Found.....!'})
    
    userData = {}
    userData['publicId'] = user.publicId
    userData['name'] = user.name
    userData['password'] = user.password    
    userData['admin'] = user.admin

    return jsonify({'user : ' : userData})

@app.route('/user', methods=['POST'])
@TokenRequired
def CreateUser(currentUser):
    if not currentUser.admin:
        return jsonify({'message' : 'You have not access to perform this operation'})
    
    data = request.get_json()

    hashPassword = generate_password_hash(data['password'], method='sha256')
    newUser = User(publicId=str(uuid.uuid4()), name=data['name'], password=hashPassword, admin=False)
    db.session.add(newUser)
    db.session.commit()
    return jsonify({'message' : 'Welcome....!!!'})

@app.route('/user/<publicId>', methods=['DELETE'])
@TokenRequired
def DeleteUser(currentUser, publicId):
    if not currentUser.admin:
        return jsonify({'message' : 'You have not access to perform this operation'})
    
    user = User.query.filter_by(publicId = publicId).first()

    if not user:
        return jsonify({'message' : 'User Not Found.....!'})
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message' : 'The User has been deleted'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not varify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(name = auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'publicId' : user.publicId, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Username & Password does not match', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/book', methods=['GET'])
@TokenRequired
def BookList(currentUser):
    books = Book.query.filter_by(userId = currentUser.id).all()
    result = []
    for item in books:
        bookData = {}
        bookData['id '] = item.id
        bookData['title'] = item.title
        bookData['amazonURL'] = item.amazonURL
        bookData['author'] = item.author
        bookData['generalInfo'] = item.generalInfo
        bookData['userId'] = item.userId
        result.append(bookData)
    
    return jsonify({'Books' : result})

@app.route('/book', methods=['POST'])
@TokenRequired
def AddBook(currentUser):
    data = request.get_json()

    newBook = Todo(text=data['text'], complete=False, user_id=currentUser.id)
    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message' : "Book Added!"})

@app.route('/book/<bookId>', methods=['POST'])
@TokenRequired
def DeleteBook(currentUser, bookId):
    item = Todo.query.filter_by(id=bookId, user_id=currentUser.id).first()

    if not item:
        return jsonify({'message' : 'No book found!'})

    db.session.delete(item)
    db.session.commit()

    return jsonify({'message' : 'Item deleted!'})

if __name__ == '__main__':
    app.run(debug=True)
