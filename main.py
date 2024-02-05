from flask import Flask, request, jsonify,render_template
from flask_sqlalchemy import SQLAlchemy
import requests
import hashlib
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
@app.route("/")
def hello_world():
    return render_template('index.html')

# Configure your MySQL connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/cloudmalvaredetectionbackend'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define your model (table structure)
class MalwareStatus(db.Model):
    __tablename__ = 'your_table_name'
    sno = db.Column(db.Integer, primary_key=True)
    malwarestatus = db.Column(db.String(80), nullable=False)
    malwaretype = db.Column(db.String(12), nullable=False)

    def __init__(self, malwarestatus, malwaretype):
        self.malwarestatus = malwarestatus
        self.malwaretype = malwaretype

def create_tables():
    with app.app_context():
        db.create_all()

known_malware_signatures_md5 = [
    "ca169e0532e26ec7389e558ad2bafd21",
    "8638fbede2d198a049dedb9180128205",
    "bddc8212383cde8ddcffe42a7fd85063",
    "15b24c5ab82c0bc165a494316c0ddcb0",
    "26de5b4792056d2e83c8e9a56cf4097c",
    "8904443e2833b71a2d06e067dd0ee359",
    "3acd7b2bbb7e18226be407e4d794b519",
    "4fd5a01fc322285f53fbccdb4c01fa14",
    "734fb7e9e85254a04eb066dc0c2b5819",
    "9fcf144371670792127d2d06f9a5e33f",
]
known_malware_signatures_sha1 = [
    "77b0e222095c44cd29d3f39fc09e30c489ae7785",
    "8deb441af07fcbc9f46cb0ed098b2a6757416878",
    "c738b3893bfb928d08eda602e278c58f550f7283",
    "8331388d8d5018790bea0605306820b8d83034c0",
    "535784c5adce2af745dda5f5900697d9412032f5",
    "3cd2f6d8140191e87ea6d3feac3cb20c02a3ac8c",
    "1b69d2b6185a800a14888db0bf7366591df4e80f",
    "a70acb698e6b9de8996650322a985867b645736c",
    "535f066498aacfbba13b721cbdb4ee760930a93b",
    "f12f2073920441ad4980e3a641986a8860fda506",
]
known_malware_signatures_sha256 = [
    "48271ee1565ae130fba1943a29dad358f98bdbd8cf8b5ef0ea8b31b31ba35092",
    "a9a6bc0ed7c76c93ba93ade5f2926e788f4d4945e0b8e9931d1c1cacca96bfe9",
    "a5e37c1991af184e7167eaa4fac7b0c0af332e22fe69596271c6aaead8b46359",
    "2bbeee0e56a8b5629092e72c78e32e69c50c5b07def76d872deb6dd4f79c9e2d",
    "2842fc4b63aed023d1287551704a2592d4a9aa03f8a345610646007eff530336",
    "dffbe653e1b01ab2ef1e698ca4f8180b8c56b8bea6abb1751f382eadc3abd2df",
    "3e7f72245fa263aebb5a818b1c0ea9f49bc24cf1a227f97e5b9109f5f96617dc",
    "7cef44b32debbc1bfb7462120c41d96290ac88beea4aa3192f634645a38cb4c7",
    "a59268012042a167c6fbcab1152c9bff91d59c9d967879d5ee63959721775b16",
    "a2c500c7713a52871d1e117a84f257b4c7071ea08aee6ca0ad34f203ec16a7f9",
]

def check_hash_and_save(file_content):
    # Initialize variables
    malware_status = 'clean'
    malware_type = 'unknown'
    detection_details = []

    # Define your hash checks
    hash_checks = [
        ('MD5', known_malware_signatures_md5, hashlib.md5),
        ('SHA-1', known_malware_signatures_sha1, hashlib.sha1),
        ('SHA-256', known_malware_signatures_sha256, hashlib.sha256)
    ]

    # Perform hash checks
    for algorithm, known_signatures, hash_func in hash_checks:
        hash_value = hash_func(file_content).hexdigest()
        status = 'detected' if hash_value in known_signatures else 'clean'
        detection_details.append({'algorithm': algorithm, 'hash': hash_value, 'status': status})

        # If any of the hashes is detected as malware, update malware_status and malware_type
        if status == 'detected':
            malware_status = 'detected'
            malware_type = algorithm  # or more specific information if available

    # Save the detection results in the database
    new_entry = MalwareStatus(malwarestatus=malware_status, malwaretype=malware_type)
    db.session.add(new_entry)
    db.session.commit()

    # Return the results and the details of detection
    return {'status': malware_status, 'type': malware_type, 'details': detection_details}
CORS(app, resources={r"/submit-malware": {"methods": ["POST"]}})
@app.route('/submit-malware', methods=['POST'])
def submit_malware():
    data = request.json
    url = data['url']

    # Download the file content from the URL
    try:
        response = requests.get(url)
        file_content = response.content

        # Check hashes and save results
        result = check_hash_and_save(file_content)

        # Respond with the result
        return jsonify({'message': 'File processed', 'result': result}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error occurred', 'error': str(e)}), 500

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
