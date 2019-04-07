from flask import Flask, jsonify, render_template
from flask import abort
from flask import make_response,request
import json
import os
import requests


app= Flask(__name__,template_folder='.')
app.config.from_object(__name__)

data =""
app.secret_key = 'my key'


#-------------------------------------------------ANDROID-APP-POST-REQUESTS-------------------------------------------------------------------------

#save details of user into database

@app.route('/', methods=['GET'])
def index():
	
	return render_template('index3.html')


@app.route('/seller', methods=['GET'])
def seller():
	cmd = os.system('python seller.py')
	return make_response(jsonify({'success': 'success'}), 200)

@app.route('/update', methods=['POST'])
def update():
	global data
	print('SUNNNNNNNNNYYYYYYYY',request.data)
	data = request.data
	#r = requests.get(url = 'http://127.0.0.1:8082/shows', data = request.data) 
		
	return make_response(jsonify({'success': 'success'}), 200)

@app.route('/show', methods=['Get'])
def show():
	global data

	return data

if __name__ == '__main__':
	app.run('127.0.0.1',8082,debug=True)
