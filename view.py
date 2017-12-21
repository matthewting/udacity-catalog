from models import Base, User, Category, Item
from flask import Flask, render_template, redirect, jsonify, request, url_for
from flask import abort, g, flash
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, desc, func
import datetime

from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

app = Flask(__name__)

# Set up client ID for OAuth
CLIENT_ID = json.loads(
    open('client_secret_626174227976.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Item Web Application"

# Create Database section
engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Verify user password
@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token
        ).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(
            'client_secret_626174227976.json',
            scope=''
        )
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)

        # Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'),
            200
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])

    # see if user exists, if it doesn't make a new one
    user = session.query(User).filter_by(
        emailAddress=login_session['email']
    ).first()
    if not user:
        user = User(
            username=login_session['username'],
            emailAddress=login_session['email']
        )
        session.add(user)
        session.commit()
        print ("user {0} is registered!".format(login_session['username']))

    login_session['UserId'] = user.id

    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    if access_token is None:
        response = make_response(
            json.dumps('Current user is not connected.'), 401
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    # User access token is found
    url = 'https://accounts.google.com/o/oauth2/revoke?token={0}'.format(
        login_session['access_token']
    )
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['UserId']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        # return response
        return redirect(url_for('showCategories'))
    else:
        # If token is expired, still logout and redirect to front page
        result2 = json.loads(h.request(url, 'GET')[1])
        if result2['error_description'] == "Token expired or revoked":
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['UserId']
            response = make_response(json.dumps(
                'Token is expired, logout anyway...'), 200
                )
            response.headers['Content-Type'] = 'application/json'
            # return response
            return redirect(url_for('showCategories'))
        # If it is a invlaid token and not expired token, report error...
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400)
            )
        response.headers['Content-Type'] = 'application/json'
        return response


# Show the whole catalog in json format
@app.route('/catalog.json')
def showItemsJSON():
    items = session.query(Item).all()
    jsonResultSet = []

    categories = session.query(Category).all()
    for category in categories:
        categoryObj = {'id': category.id, 'name': category.name}

        categoryItems = [{
                        "cat_id": item.category_id,
                        "description": item.description,
                        "id": item.id,
                        "title": item.title} for item in items if
                            item.category_id == category.id]
        if(len(categoryItems) > 0):
            categoryObj["Item"] = categoryItems

        jsonResultSet.append(categoryObj)
    return jsonify(Category=[item for item in jsonResultSet])


# routing to show all the categories and latest items
@app.route('/')
@app.route('/catalog/')
def showCategories():
    # In showCategories page
    categories = session.query(Category).order_by(Category.id)
    items = session.query(Item).order_by(desc(Item.added_on))
    return render_template(
                        'catalog.html', categories=categories, items=items,
                        login_session=login_session
    )


# routing to show specific Category's items
@app.route('/catalog/<string:name>/')
def showItems(name):
    # In showItems page
    categories = session.query(Category).order_by(Category.id)
    category = session.query(Category).filter(
        func.lower(Category.name) == func.lower(name)
    ).one()
    items = session.query(Item).filter_by(
        category_id=category.id
    ).order_by(desc(Item.added_on))
    return render_template(
        'showItems.html', categories=categories, category=category,
        items=items, login_session=login_session
    )


# routing to show specific item details:
@app.route('/catalog/<string:categoryName>/<string:itemName>/')
def showItemDetails(categoryName, itemName):
    # In showItemDetails page
    item = session.query(Item).filter(
        func.lower(Item.title) == func.lower(itemName)
    ).one()
    return render_template(
        'viewItem.html', item=item, login_session=login_session
    )


# routing to edit item details:
@app.route('/catalog/<string:itemName>/edit/', methods=['GET', 'POST'])
def editItem(itemName):
    if 'username' not in login_session:
        return redirect('/login')

    user = session.query(User).filter_by(
        emailAddress=login_session['email']
    ).one_or_none()

    if (user is None):
        response = make_response(json.dumps(result.get('error')), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    userID = user.id

    item = session.query(Item).filter(
        func.lower(Item.title) == func.lower(itemName)
    ).one()

    if (item.added_by_user_id != userID):
        response = make_response(json.dumps(
            'Item not belongs to current user or not found.', 400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response 

    if (request.method == 'POST'):
        item.description = request.form['description']
        item.title = request.form['title']
        item.category_id = request.form['categoryID']

        # Item is updated successfully
        return redirect(
                        url_for(
                            'showItemDetails',
                            categoryName=item.category.name,
                            itemName=item.title
                        )
        )

    return render_template(
                        'editItem.html',
                        item=item,
                        login_session=login_session
    )


# routing to add item:
@app.route('/catalog/new/<string:category_id>', methods=['GET', 'POST'])
def createItem(category_id):
    if 'username' not in login_session:
        return redirect('/login')

    user = session.query(User).filter_by(
            emailAddress=login_session['email']
    ).one_or_none()

    if (user is None):
        response = make_response(json.dumps(result.get('error')), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    userID = user.id

    if (request.method == 'POST'):
        totalItems = session.query(func.max(Item.id)).scalar()
        newItemDescription = request.form['description']
        newItemTitle = request.form['title']
        category_id = request.form['categoryID']
        itemID = totalItems + 1
        newItem = Item(
                    id=itemID,
                    title=newItemTitle,
                    description=newItemDescription,
                    added_on=datetime.datetime.utcnow(),
                    category_id=category_id,
                    added_by_user_id=user.id
        )
        session.add(newItem)
        session.commit()

        # Item is added sucessfully
        return redirect(
                        url_for(
                            'showItemDetails',
                            categoryName=newItem.category.name,
                            itemName=newItem.title
                        )
        )

    return render_template(
                        'newItem.html',
                        login_session=login_session,
                        category_id=category_id
    )


# Routing to delete an item:
@app.route('/catalog/<int:itemID>/delete/', methods=['GET', 'POST'])
def deleteItem(itemID):
    # In deleteItem
    if 'username' not in login_session:
        return redirect('/login')
    deletingItem = session.query(Item).filter_by(id=itemID).one()

    user = session.query(User).filter_by(
        emailAddress=login_session['email']
    ).one_or_none()

    if (user is None):
        response = make_response(json.dumps(result.get('error')), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    userID = user.id

    if (deletingItem.added_by_user_id != userID):
        response = make_response(json.dumps(
            'Item not belongs to current user or not found.', 400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    if (request.method == 'POST'):
        # Deleting item
        session.delete(deletingItem)
        session.commit()
        return redirect(url_for('showCategories'))

    return render_template(
                'deleteItem.html',
                item=deletingItem,
                login_session=login_session
    )


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
