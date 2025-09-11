from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from azure.storage.blob import BlobServiceClient
import os

app = FastAPI()

# Serve static files (including index.html)
app.mount("/", StaticFiles(directory=".", html=True), name="static")

# Environment variables
AZURE_CONNECTION_STRING = os.environ["STORAGE_CONNECTION"]
CONTAINER_NAME = "webfiles"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

# Upload endpoint
@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    try:
        blob_client = container_client.get_blob_client(file.filename)
        data = await file.read()
        blob_client.upload_blob(data, overwrite=True)
        return {"filename": file.filename, "status": "uploaded"}
    except Exception as e:
        return {"error": str(e)}
