from flask import Flask, render_template, url_for, request, redirect
from pymongo import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)

uri = "mongodb+srv://liuseemin:bZVnix0Egiye6cD3@cluster0.l8tth.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = MongoClient('localhost', 27017)

# client = MongoClient(uri, server_api=ServerApi('1'))

# database
db = client.flask_database

# collection
todos = db.todos

@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'POST':
        content = request.form['content']
        importance = request.form['importance']
        todos.insert_one({'content': content, 'importance': importance})
        return redirect(url_for('index'))
    all_todos = todos.find()
    return render_template('index.html', todos=all_todos)

if __name__ == "__main__":
    app.run(debug=True)