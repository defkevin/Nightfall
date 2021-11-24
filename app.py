import hmac
import hashlib
import os
from datetime import datetime, timedelta
from os import environ, path, mkdir

from flask import Flask, request
import requests

app = Flask(__name__)

output_dir = "findings"

SIGNING_SECRET = os.environ.get("SIGNING_SECRET")

# If using pycharm, this can be found by right clicking on your
JSON_OUTPUT_FOLDER = "your_package_absolute_path"

JSON_CODE_BEAUTIFY_URL = "https://codebeautify.org/jsonviewer"

# threshold (in minutes) to check against to verify incoming webhook request validity
THRESHOLD_TIME = 5

@app.route("/", methods=['POST'])
def webhook_url():
    content = request.get_json(silent=True)

    challenge = content.get("challenge")
    if challenge:
        return "text_to_make_challenge_fail"

    # This code will only be reached if the challenge has already been passed
    else:
        verify_signature_and_verify_timestamp_is_within_threshold(THRESHOLD_TIME)

        print(F"Received request metadata: {content['requestMetadata']}")
        print(F"Received errors: {content['errors']}")

        if not content["findingsPresent"]:
            print(F"No findings for {content['uploadID']}")
            return "", 200
        print(F"S3 findings valid until {content['validUntil']}")
        response = requests.get(content["findingsURL"])
        json_absolute_file_path = JSON_OUTPUT_FOLDER + save_findings(content["uploadID"], response.text)
        with open(json_absolute_file_path, 'r') as myfile:
            data = myfile.read()
        print("Findings results: " + data)
        print("Please copy and paste above json payload into " + JSON_CODE_BEAUTIFY_URL + " for readable formatting.")
        return "", 200

# We recommend a threshold of 5 minutes according to industry best practices
def verify_signature_and_verify_timestamp_is_within_threshold(threshold):
    if SIGNING_SECRET is None:
        return

    given_signature = request.headers.get('X-Nightfall-Signature')
    req_timestamp = request.headers.get('X-Nightfall-Timestamp')
    now = datetime.now()

    # debugged this timestamp check to make sure timestamps are in sequential order
    if now - timedelta(minutes=threshold) > datetime.fromtimestamp(int(req_timestamp)) or datetime.fromtimestamp(int(req_timestamp)) > now:
        raise Exception("could not validate timestamp is within the last few minutes")
    computed_signature = hmac.new(
        SIGNING_SECRET.encode(),
        msg=F"{req_timestamp}:{request.get_data(as_text=True)}".encode(),
        digestmod=hashlib.sha256
    ).hexdigest().lower()
    if computed_signature != given_signature:
        raise Exception("could not validate signature of inbound request!")


def save_findings(scan_id, finding_json):
    if not path.isdir(output_dir):
        mkdir(output_dir)
    output_path = path.join(output_dir, f"{scan_id}.json")
    with open(output_path, "w+") as out_file:
        out_file.write(finding_json)
    print(F"Findings for {scan_id} written to {output_path}")
    return output_path

if __name__ == "__main__":
    app.run(port=5000, debug=True)