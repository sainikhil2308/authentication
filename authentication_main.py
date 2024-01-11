from flask import Flask, request, jsonify
import mysql.connector
from werkzeug.security import  generate_password_hash
import jwt
import datetime
import secrets
from werkzeug.utils import secure_filename
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import os


app=Flask(__name__)
secret_key=secrets.token_hex(16)
app.config['SECRET_KEY']=secret_key
print("Secret Key:", secret_key)
print("gadsf")

conn=mysql.connector.connect(host='localhost', user='root', password='Nikhil1234$',database='data1')
cursor=conn.cursor()

AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
CONTAINER_NAME = 'container_name'


@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data['username']
    password = generate_password_hash(data['password'])
    
    

    try:
        # Storing the hashed password in the database
        query = ("INSERT INTO users (username, password) "
                 "VALUES (%s, %s)")
        cursor.execute(query, (username, password))
        conn.commit()
    except mysql.connector.Error as err:
        # Handle errors like duplicate entry, etc.
        print("Error:", err)
        return {"message": "Failed to create user"}, 500
    finally:
        cursor.close()
        conn.close()

    token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'message': 'User created successfully', 'token': token}), 201


@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'message': 'No image part'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    image_url = upload_to_azure_blob(file, filename)
    
    insert_query = f"""INSERT INTO users(pic_url) VALUES ('{image_url}')""" 
    cursor.execute(insert_query)


    return jsonify({'message': 'Image uploaded successfully', 'url': image_url}), 200

def upload_to_azure_blob(file_stream, file_name):
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=file_name)

    blob_client.upload_blob(file_stream, overwrite=True)

    return blob_client.url

if __name__ == '__main__':
    app.run(debug=True)
