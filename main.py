from flask import Flask, request, send_from_directory, jsonify
from azure.storage.blob import BlobServiceClient
import os

app = Flask(__name__, static_folder=".", static_url_path="")

# Environment variables
AZURE_CONNECTION_STRING = os.environ["STORAGE_CONNECTION"]
CONTAINER_NAME = "webfiles"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

# Serve index.html and other static files
@app.route("/")
def serve_index():
    return send_from_directory(".", "index.html")

# Upload endpoint
@app.route("/upload/", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        blob_client = container_client.get_blob_client(file.filename)
        blob_client.upload_blob(file.read(), overwrite=True)

        return jsonify({"filename": file.filename, "status": "uploaded"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
