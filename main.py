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
from PIL import Image
import io

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

# -----------------------------------------------------------
# CAMERA ORIENTATION -- handled automatically
# -----------------------------------------------------------
# Earlier versions of this file manually rotated images 180
# degrees here on the server, based on a fixed assumption
# about how the camera was mounted. That approach broke every
# time the camera's physical position changed between tests.
#
# OCR.space's own "detectOrientation" option (enabled below,
# in the API call itself) already looks at the actual text in
# each photo and corrects its orientation automatically, photo
# by photo -- regardless of how the camera happened to be
# positioned when that specific photo was taken. This is more
# reliable than guessing a single fixed rotation, so manual
# rotation has been removed entirely.
# -----------------------------------------------------------


def _ocr_attempt(image_bytes: bytes) -> str:
    """
    Sends ONE version of the photo to OCR.space and returns
    whatever plate-like text it can find, or "" if nothing
    usable came back. This is the single-attempt building
    block -- extract_plate_text() below calls this twice
    (original, then rotated) if needed.
    """
    try:
        response = requests.post(
            OCR_SPACE_URL,
            files={"file": ("plate.jpg", image_bytes, "image/jpeg")},
            data={
                "apikey": OCR_SPACE_API_KEY,
                "OCREngine": "3",          # Engine 3 -- highest accuracy,
                                            # worth the extra processing time
                                            # for short plate text. Has its
                                            # own separate free quota (2,500/mo)
                                            # from Engine 1/2's 25,000/mo, so
                                            # switching doesn't use up your
                                            # main quota faster.
                "scale": "true",
                "detectOrientation": "true",
            },
            timeout=20,
        )
        result = response.json()

        parsed_results = result.get("ParsedResults", [])
        if not parsed_results:
            return ""

        # Log what OCR.space's own orientation detection reported,
        # so we can see whether it's actually catching upside-down
        # plates or not, rather than guessing.
        text_orientation = parsed_results[0].get("TextOrientation", "unknown")
        print(f"OCR detected text orientation: {text_orientation} degrees")

        raw_text = parsed_results[0].get("ParsedText", "")
        raw_text = raw_text.upper().replace("\n", " ").replace("\r", " ")

        # OCR.space sometimes returns a literal message like
        # "No text detected." as the ParsedText itself, when it
        # processed the image fine but found nothing readable.
        # Catch this explicitly -- otherwise the fallback below
        # would mangle that message into something that LOOKS
        # like a real plate (e.g. "NOTEXTDETECTED"), which is
        # wrong: it means no vehicle/plate was actually visible,
        # not that a plate was found.
        no_text_markers = ["NO TEXT DETECTED", "NOTEXTDETECTED"]
        stripped = raw_text.strip().rstrip(".!")
        if not stripped or any(marker in stripped for marker in no_text_markers):
            return ""

        # Zimbabwean plates print the word "ZIMBABWE" near the
        # coat of arms -- OCR sometimes reads this too and glues
        # it onto the plate text (e.g. "6793PZIMBABWE"). Strip it
        # out BEFORE pattern matching, so it can't contaminate
        # the result.
        text_for_matching = re.sub(r"ZIMBABWE", " ", raw_text)

        # Real Zimbabwean plates (since 2006) are an EXACT format:
        # 3 letters, then 4 digits (e.g. "ABC 1234"). Matching this
        # precisely -- not "2-3 letters + 1-4 digits" -- is what
        # actually filters out garbled OCR fragments like "679AGP"
        # or "9AGP4", which technically contain letters and digits
        # but aren't a real 3-letter+4-digit plate at all.
        match = re.search(r"\b[A-Z]{3}[\s-]?\d{4}\b", text_for_matching)
        if match:
            candidate = match.group(0).replace(" ", "").replace("-", "")
            return candidate

        # Nothing matched the exact real plate format -- whatever
        # OCR saw isn't a genuine, fully-readable plate. Rather
        # than guessing from a loose fallback cleanup (which is
        # what let scrambled fragments through before), report
        # this as unreadable.
        return ""

    except Exception as e:
        print(f"OCR error: {e}")
        return ""


def extract_plate_text(image_bytes: bytes) -> str:
    """
    Tries to read a plate from the photo. OCR.space's own
    "detectOrientation" setting usually corrects upside-down
    text on its own, but real testing showed it doesn't always
    catch plate-style fonts reliably. As a backup, if the first
    attempt finds nothing usable, this automatically retries
    with the image rotated 180 degrees -- so it works whether
    the camera happens to be right-side-up or upside-down at
    any given moment, with no fixed assumption either way.
    """
    first_try = _ocr_attempt(image_bytes)
    if first_try:
        return first_try

    print("First OCR attempt found nothing usable -- retrying with image rotated 180 degrees...")
    try:
        img = Image.open(io.BytesIO(image_bytes))
        rotated = img.rotate(180, expand=True)
        output = io.BytesIO()
        rotated.save(output, format="JPEG")
        rotated_bytes = output.getvalue()
    except Exception as e:
        print(f"Could not rotate image for retry: {e}")
        return ""

    second_try = _ocr_attempt(rotated_bytes)
    if second_try:
        print("Rotated retry succeeded.")
    return second_try

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
#   "amountPaid": "450.00"
# }
#
# "status" can be one of THREE things:
#   "PAID"      -- plate was read and found, duty is paid
#   "NOTPAID"   -- plate was read, but not found, or found
#                  and marked unpaid
#   "NOVEHICLE" -- OCR found NO readable plate text at all in
#                  the photo. This usually means there genuinely
#                  was no vehicle in frame (just background,
#                  ground, etc), or the photo was too blurry/
#                  dark to read anything at all. The ESP32 code
#                  shows a distinct "no vehicle detected" screen
#                  for this case, instead of treating it like an
#                  actual unpaid vehicle.
# -----------------------------------------------------------
def build_response(plate_id: str, data: dict | None, no_vehicle: bool = False) -> dict:
    """Builds the JSON shape sent back to the ESP32-CAM.

    no_vehicle=True means OCR found no plate text at all --
    this is reported as its own status, separate from a real
    "not paid" result, since they mean very different things.
    """
    if no_vehicle:
        return {
            "plate": "",
            "status": "NOVEHICLE",
            "owner": "",
            "amountPaid": "",
        }
    if data is None:
        return {
            "plate": plate_id,
            "status": "NOTPAID",
            "owner": "",
            "amountPaid": "",
        }
    return {
        "plate": data.get("plate", plate_id),
        "status": data.get("status", "NOTPAID"),
        "owner": data.get("owner", ""),
        "amountPaid": data.get("amountPaid", ""),
    }


@app.post("/api/check")
async def check_duty(request: Request):
    if db is None:
        return build_response("", None)

    image_bytes = await request.body()

    if not image_bytes:
        # No photo data at all was sent -- nothing to check
        return build_response("", None, no_vehicle=True)

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
        # OCR found no readable plate text at all -- most likely
        # no vehicle was actually in frame, or the photo was too
        # blurry/dark. Report this as its own distinct status.
        return build_response("", None, no_vehicle=True)

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