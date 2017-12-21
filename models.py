from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import datetime
import random
import string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer,
                         BadSignature, SignatureExpired)

# set up for password encryption
Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase +
             string.digits) for x in xrange(32))

# User class
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    emailAddress = Column(String(32), index=True)    
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)
    
    def verify_password(self, password):
        print("verifying password: {0}".format(password))
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']
    	return user_id


# Category class
class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {
        'name' : self.name,
        'id' : self.id
        }

# Item class
class Item(Base):
    __tablename__ = 'menu_item'

    id = Column(Integer, primary_key = True)
    title = Column(String(80), nullable=False)
    description = Column(String(250))
    added_on = Column(DateTime, default=datetime.datetime.utcnow())
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    added_by_user_id = Column(Integer,ForeignKey('user.id'))
    added_by_user = relationship(User)

    @property
    def serialize(self):
        """Return object data in serializable format for API user"""
        return {
        'title' : self.title,
        'description' : self.description,
        'addedOn' : self.added_on,
        }

engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)



