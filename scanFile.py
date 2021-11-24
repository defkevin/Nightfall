from nightfall import Nightfall
import os
import sys

"""
Replace these two fields with respective UUID's and webhook_url
"""
DETECTION_RULE_UUIDS = ['990315de-92d1-4eb8-830d-6d912bf5ebb6']
WEBHOOK_URL = "https://3c30-174-127-175-51.ngrok.io"
API_KEY = os.environ.get("API_KEY")
SIGNING_SECRET = os.environ.get("SIGNING_SECRET")

if __name__ == "__main__":
    # filename must be the absolute path
    filename = sys.argv[1]
    nightfall = Nightfall(API_KEY, SIGNING_SECRET)
    result, _ = nightfall.scan_file(filename, WEBHOOK_URL, detection_rule_uuids=DETECTION_RULE_UUIDS)
    print("Response Id: " + str(result))
    print("Please look into flask logs for Findings")
