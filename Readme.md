# ud036_StarterCode
Build an Item Catalog Application Project
An application that provides a list of items within a variety of categories as welll as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

Install
Run "python view.py" to initiate the web server to set up the front page for this application.

How to use
After the views is set up. User can login with the google plus account and the system will automatically reigsterd them into the local database, using email as the identifier. All the CRUD actions about the items are binded to the current user that operating those actions. Only the registered users who created the item can edit or delete it, otherwise he can only view the details like description and category.
Besides all the formal create, read, update, delete operations, this application can also print out all the items in json by calling http://localhost:8000/catalog.json url

## Creator
This page is built by Matthew Ting(matthewting@gmail.com)

## Copyright and License
This is a public domain work. Feel free to do whatever you want with it.
Copyright 2017 Matthew Ting.



