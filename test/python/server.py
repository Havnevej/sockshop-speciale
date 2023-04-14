from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/')
def index():
    return 'Welcome to my website!'

@app.route('/search')
def search():
    query = request.args.get('q')
    result = os.system('ls ./images/' + query)
    return 'Search results for: ' + result

if __name__ == '__main__':
    app.run()

