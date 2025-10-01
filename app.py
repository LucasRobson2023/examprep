from flask import Flask, request, send_from_directory, jsonify, redirect, url_for, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.monitor.opentelemetry import configure_azure_monitor
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os, time

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

# ---------------- Database Setup (SQLite) ----------------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Create DB tables if not exist
with app.app_context():
    db.create_all()
    if User.query.count() == 0:
        default_users = [
            ("admin", "password123"),
            ("bob", "mypassword"),
            ("alice", "test123")
        ]
        for username, pwd in default_users:
            u = User(username=username)
            u.set_password(pwd)
            db.session.add(u)
        db.session.commit()
        print("✅ Default users added to database")

# ---------------- Flask-Login Setup ----------------
login_manager = LoginManager()
login_manager.login_view = "login"   # redirect to /login if not logged in
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
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

        # VULNERABLE SQL INJECTION IMPLEMENTATION
        # Using SQLAlchemy's text() with string concatenation - UNSAFE!
        try:
            from sqlalchemy import text
            
            # ⚠️ VULNERABLE CODE: Direct string concatenation in SQL
            query = text(f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{generate_password_hash(password)}'")
            
            # Execute the vulnerable query
            result = db.session.execute(query)
            user_data = result.fetchone()
            
            if user_data:
                # Convert result to User object
                user = User.query.get(user_data[0])
                if user:
                    login_user(user)
                    return redirect(url_for("serve_index"))
            
            return "Invalid credentials", 401
            
        except Exception as e:
            return f"Database error: {str(e)}", 500

    return send_from_directory(".", "login.html")

@app.route("/secure-login", methods=["GET", "POST"])
def secure_login():
    """This is the secure version for comparison"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # ✅ SECURE: Using SQLAlchemy's proper parameterized queries
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("serve_index"))
        return "Invalid credentials", 401

    return send_from_directory(".", "secure_login.html")

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
