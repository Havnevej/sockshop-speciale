import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Insecure authentication logic
    if username == 'admin' and password == 'password':
        return 'Logged in as admin'
    else:
        return 'Invalid username or password'

@app.route('/execute', methods=['POST'])
def execute():
    command = request.form.get('command')

    # Insecure command execution
    result = subprocess.check_output(command, shell=True)
    return result

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
