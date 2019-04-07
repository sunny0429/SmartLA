from flask import Flask, jsonify, render_template
from flask import abort
from flask import make_response,request
import json
import os



app= Flask(__name__,template_folder='.')
app.config.from_object(__name__)


app.secret_key = 'my key'
data=""

#-------------------------------------------------ANDROID-APP-POST-REQUESTS-------------------------------------------------------------------------

#save details of user into database
@app.route('/buyer', methods=['GET'])
def buyer():
	cmd = os.system('python buyer.py')
	return make_response(jsonify({'success': 'success'}), 200)

@app.route('/update', methods=['POST'])
def update():
	global data
	print('SUNNNNNNNNNYYYYYYYY',request.data)
	data = request.data

	return make_response(jsonify({'success': 'success'}), 200)


@app.route('/', methods=['GET'])
def index():
	
	return render_template('index_buyer.html')

@app.route('/show', methods=['Get'])
def show():
	global data
	return data


if __name__ == '__main__':
	app.run('127.0.0.1',8083,debug=True)
