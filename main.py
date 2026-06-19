# ===========================================================
# ZIMRA Duty Check -- Lookup Server
# MPKComteck Technology Solutions
# ===========================================================
#
# WHAT THIS SERVER DOES:
# The ESP32-CAM sends a number plate (as plain text) to this
# server. This server looks up that plate in Firestore and
# replies with either "PAID" or "NOTPAID" as plain text.
#
# This runs on Render.com's free tier -- NOT on Firebase --
# because Firebase Hosting alone cannot run server-side code
# without the paid Blaze plan. This server still reads and
# writes to your Firestore database, which IS free.
#
# ===========================================================

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json
import re
import requests

app = FastAPI()

# -----------------------------------------------------------
# OCR.SPACE SETUP -- reads the plate text out of the photo
# -----------------------------------------------------------
# Get a free key at: https://ocr.space/ocrapi/freekey
# On Render.com, set this as an environment variable called
# OCR_SPACE_API_KEY
# -----------------------------------------------------------
OCR_SPACE_API_KEY = os.environ.get("OCR_SPACE_API_KEY", "helloworld")
OCR_SPACE_URL = "https://api.ocr.space/parse/image"


def extract_plate_text(image_bytes: bytes) -> str:
    """
    Sends the photo to OCR.space, gets back whatever text it
    can read, then picks out something that looks like a
    Zimbabwean-style plate (letters followed by numbers).
    Returns an empty string if nothing usable was found.
    """
    try:
        response = requests.post(
            OCR_SPACE_URL,
            files={"file": ("plate.jpg", image_bytes, "image/jpeg")},
            data={
                "apikey": OCR_SPACE_API_KEY,
                "OCREngine": "2",          # better for short, noisy text
                "scale": "true",
                "detectOrientation": "true",
            },
            timeout=20,
        )
        result = response.json()

        parsed_results = result.get("ParsedResults", [])
        if not parsed_results:
            return ""

        raw_text = parsed_results[0].get("ParsedText", "")
        raw_text = raw_text.upper().replace("\n", " ").replace("\r", " ")

        # Look for a plate-like pattern: 2-3 letters + 1-4 digits
        # (adjust this pattern later to match real ZIMRA plate formats)
        match = re.search(r"[A-Z]{2,3}[\s-]?\d{2,4}", raw_text)
        if match:
            return match.group(0).replace(" ", "").replace("-", "")

        # Fallback: strip everything except letters/numbers and
        # return it as-is if OCR found anything at all
        cleaned = re.sub(r"[^A-Z0-9]", "", raw_text)
        return cleaned

    except Exception as e:
        print(f"OCR error: {e}")
        return ""

# -----------------------------------------------------------
# FIREBASE SETUP
# -----------------------------------------------------------
# You need a "service account key" JSON file from Firebase.
# Get it from: Firebase Console -> Project Settings ->
# Service Accounts tab -> Generate new private key
#
# On Render.com, paste the FULL CONTENTS of that JSON file
# into an environment variable called FIREBASE_CREDENTIALS_JSON
# (Render dashboard -> Environment -> Add Environment Variable)
# -----------------------------------------------------------

firebase_creds_raw = os.environ.get("FIREBASE_CREDENTIALS_JSON")
local_key_file = "firebase-key.json"

if firebase_creds_raw:
    # Used on Render.com, where the key is set as an environment variable
    cred_dict = json.loads(firebase_creds_raw)
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
elif os.path.exists(local_key_file):
    # Used for local testing on your laptop -- just place the
    # downloaded JSON file in this same folder, named
    # "firebase-key.json", no copy-pasting needed
    cred = credentials.Certificate(local_key_file)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print(f"Loaded Firebase credentials from local file: {local_key_file}")
else:
    # Neither method found -- server still starts, but lookups
    # will fail with a clear error
    db = None
    print("WARNING: No Firebase credentials found. Either set")
    print("FIREBASE_CREDENTIALS_JSON, or place a file named")
    print(f"'{local_key_file}' in this folder. Firestore lookups will fail.")


# -----------------------------------------------------------
# HEALTH CHECK -- visit this URL in a browser to confirm
# the server is alive at all
# -----------------------------------------------------------
@app.get("/")
def health_check():
    return {"status": "ZIMRA Duty Check server is running"}


# -----------------------------------------------------------
# DEBUG ENDPOINT -- view the most recent photo the camera sent
# -----------------------------------------------------------
# Visit this in a browser after triggering a scan, to see
# exactly what the ESP32-CAM captured. Helps a lot when OCR
# isn't reading anything -- you can SEE if the photo is blurry,
# glared, too dark, or just not framed on the plate.
# -----------------------------------------------------------
from fastapi.responses import FileResponse
import os

@app.get("/api/last-photo")
def get_last_photo():
    if os.path.exists("last_photo.jpg"):
        return FileResponse("last_photo.jpg", media_type="image/jpeg")
    return {"error": "No photo received yet. Trigger a scan first."}


# -----------------------------------------------------------
# MAIN ENDPOINT -- the ESP32-CAM sends a PHOTO here
# -----------------------------------------------------------
# Expected request: POST /api/check
# Body: raw JPEG photo bytes (this is what the ESP32 code sends)
#
# This endpoint reads the plate text out of the photo using
# OCR.space, then looks that plate up in Firestore.
#
# Response: JSON, e.g.
# {
#   "plate": "ACP1234",
#   "status": "PAID",
#   "owner": "T. Moyo",
#   "amountPaid": "450.00",
#   "expiryDate": "02/06/2027"
# }
#
# If the plate can't be read or isn't found, status will be
# "NOTPAID" and the other fields will be empty strings -- the
# ESP32 code is written to handle that gracefully.
# -----------------------------------------------------------
def build_response(plate_id: str, data: dict | None) -> dict:
    """Builds the JSON shape sent back to the ESP32-CAM, whether
    or not a matching record was found."""
    if data is None:
        return {
            "plate": plate_id,
            "status": "NOTPAID",
            "owner": "",
            "amountPaid": "",
            "expiryDate": "",
        }
    return {
        "plate": data.get("plate", plate_id),
        "status": data.get("status", "NOTPAID"),
        "owner": data.get("owner", ""),
        "amountPaid": data.get("amountPaid", ""),
        "expiryDate": data.get("expiryDate", ""),
    }


@app.post("/api/check")
async def check_duty(request: Request):
    if db is None:
        return build_response("", None)

    image_bytes = await request.body()

    if not image_bytes:
        return build_response("", None)

    # DEBUG: save the most recent photo received, so you can
    # open it and SEE exactly what the camera captured. This
    # overwrites the same file each time -- it's just for
    # troubleshooting, not permanent storage.
    try:
        with open("last_photo.jpg", "wb") as f:
            f.write(image_bytes)
        print(f"Saved debug photo: last_photo.jpg ({len(image_bytes)} bytes)")
    except Exception as e:
        print(f"Could not save debug photo: {e}")

    # Step 1: read the plate text out of the photo
    plate_id = extract_plate_text(image_bytes)
    print(f"OCR read plate as: '{plate_id}'")

    if not plate_id:
        # Could not read anything usable from the photo
        return build_response("", None)

    # Step 2: look that plate up in Firestore
    doc_ref = db.collection("vehicles").document(plate_id)
    doc = doc_ref.get()

    if doc.exists:
        return build_response(plate_id, doc.to_dict())
    else:
        # Plate not found in database -- treat as not paid,
        # since we have no record of payment
        return build_response(plate_id, None)


# -----------------------------------------------------------
# ALTERNATE ENDPOINT -- for testing with a plate number
# typed directly into a browser URL, without needing the
# ESP32-CAM or Postman
# -----------------------------------------------------------
@app.get("/api/check-test/{plate}")
async def check_duty_test(plate: str):
    if db is None:
        return build_response(plate, None)

    plate_id = plate.strip().upper().replace(" ", "")
    doc_ref = db.collection("vehicles").document(plate_id)
    doc = doc_ref.get()

    if doc.exists:
        return build_response(plate_id, doc.to_dict())
    else:
        return build_response(plate_id, None)