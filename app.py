from flask import Flask, request, send_from_directory, jsonify, redirect, url_for, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.monitor.opentelemetry import configure_azure_monitor
from werkzeug.security import generate_password_hash, check_password_hash
import os, time, sqlite3

# ---------------- App Insights ----------------
APPINSIGHTS_CONNECTION_STRING = os.environ.get("APPINSIGHTS_CONNECTION_STRING")
if APPINSIGHTS_CONNECTION_STRING:
    configure_azure_monitor(
        connection_string=APPINSIGHTS_CONNECTION_STRING,
        enable_live_metrics=True
    )

app = Flask(__name__, static_folder=".", static_url_path="")

# 🔑 Flask session secret
app.secret_key = os.environ.get("FLASK_SECRET", "supersecret")

# ---------------- Database Setup (SQLite3) ----------------
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Check if we need to add default users
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    
    if count == 0:
        default_users = [
            ("admin", generate_password_hash("password123")),
            ("bob", generate_password_hash("mypassword")),
            ("alice", generate_password_hash("test123"))
        ]
        
        cursor.executemany(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            default_users
        )
        print("✅ Default users added to database")
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# ---------------- Flask-Login Setup ----------------
login_manager = LoginManager()
login_manager.login_view = "login"   # redirect to /login if not logged in
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
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

        # VULNERABLE SQL INJECTION - Direct string concatenation
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # This is vulnerable to SQL injection - username is directly concatenated
        query = f"SELECT id, username, password_hash FROM users WHERE username = '{username}'"
        cursor.execute(query)
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user = User(user_data[0], user_data[1], user_data[2])
            if user.check_password(password):
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
        blob_name = f"{current_user.username}/{file.filename}"   # user-specific folder
        blob_client = container_client.get_blob_client(blob_name)
        blob_client.upload_blob(file.read(), overwrite=True)

        return jsonify({"filename": file.filename, "status": "uploaded"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/files", methods=["GET"])
@login_required
def list_files():
    container_client = get_container_client()
    prefix = f"{current_user.username}/"
    blobs = container_client.list_blobs(name_starts_with=prefix)
    files = [blob.name.split("/", 1)[1] for blob in blobs]  # strip user prefix
    return jsonify(files)

@app.route("/download/<filename>", methods=["GET"])
@login_required
def download_file(filename):
    container_client = get_container_client()
    blob_client = container_client.get_blob_client(f"{current_user.username}/{filename}")

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
    blob_client = container_client.get_blob_client(f"{current_user.username}/{filename}")

    if not blob_client.exists():
        return jsonify({"error": "File not found"}), 404

    blob_client.delete_blob()
    return jsonify({"status": "deleted", "filename": filename})
# ---------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
