from flask import Flask, request, send_from_directory, jsonify, redirect, url_for, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os, time

app = Flask(__name__, static_folder=".", static_url_path="")

# 🔑 Flask session secret
app.secret_key = os.environ.get("FLASK_SECRET", "supersecret")

# ---------------- Flask-Login Setup ----------------
login_manager = LoginManager()
login_manager.login_view = "login"   # redirect to /login if not logged in
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

VALID_USERS = {
    "admin": "password123",   # ⚠️ Replace before production
    "bob": "mypassword"
}

@login_manager.user_loader
def load_user(user_id):
    if user_id in VALID_USERS:
        return User(user_id)
    return None
# ---------------------------------------------------

# Env vars from App Service
KEYVAULT_URL = os.environ["KEYVAULT_URL"]
SECRET_NAME = os.environ.get("SECRET_NAME", "storage-account-key1")
STORAGE_ACCOUNT_NAME = os.environ["STORAGE_ACCOUNT_NAME"]
CONTAINER_NAME = "webfiles"

credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=KEYVAULT_URL, credential=credential)

def get_blob_service_client():
    secret = secret_client.get_secret(SECRET_NAME)
    storage_key = secret.value
    conn_str = (
        f"DefaultEndpointsProtocol=https;"
        f"AccountName={STORAGE_ACCOUNT_NAME};"
        f"AccountKey={storage_key};"
        f"EndpointSuffix=core.windows.net"
    )
    return BlobServiceClient.from_connection_string(conn_str)

last_refresh = 0
refresh_interval = 600
blob_service_client = None

def get_container_client():
    global blob_service_client, last_refresh
    if time.time() - last_refresh > refresh_interval or blob_service_client is None:
        blob_service_client = get_blob_service_client()
        last_refresh = time.time()
    return blob_service_client.get_container_client(CONTAINER_NAME)

# ---------------- Routes ----------------
@app.route("/")
@login_required
def serve_index():
    return send_from_directory(".", "index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username in VALID_USERS and VALID_USERS[username] == password:
            user = User(id=username)
            login_user(user)
            return redirect(url_for("serve_index"))
        return "Invalid credentials", 401

    return send_from_directory(".", "login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------------- File Routes ----------------
@app.route("/upload/", methods=["POST"])
@login_required
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        container_client = get_container_client()
        blob_name = f"{current_user.id}/{file.filename}"   # user-specific folder
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(file.read(), overwrite=True)

        return jsonify({"filename": file.filename, "status": "uploaded"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/files", methods=["GET"])
@login_required
def list_files():
    container_client = get_container_client()
    prefix = f"{current_user.id}/"
    blobs = container_client.list_blobs(name_starts_with=prefix)
    files = [blob.name.split("/", 1)[1] for blob in blobs]  # strip user prefix
    return jsonify(files)


@app.route("/download/<filename>", methods=["GET"])
@login_required
def download_file(filename):
    container_client = get_container_client()
    blob_client = container_client.get_blob_client(f"{current_user.id}/{filename}")

    if not blob_client.exists():
        return jsonify({"error": "File not found"}), 404

    stream = blob_client.download_blob()
    return Response(
        stream.readall(),
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/octet-stream"
        }
    )


@app.route("/delete/<filename>", methods=["DELETE"])
@login_required
def delete_file(filename):
    container_client = get_container_client()
    blob_client = container_client.get_blob_client(f"{current_user.id}/{filename}")

    if not blob_client.exists():
        return jsonify({"error": "File not found"}), 404

    blob_client.delete_blob()
    return jsonify({"status": "deleted", "filename": filename})
# ---------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
