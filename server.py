from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import os
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "https://scamify-frontend.vercel.app/"}})

# Load Model & Features
model_path = "phishing_model.pkl"
feature_path = "feature_names.pkl"


if os.path.exists(model_path) and os.path.exists(feature_path):
    model = joblib.load(model_path)
    feature_names = joblib.load(feature_path)
    expected_feature_count = len(feature_names)
    print(f"Model & Features Loaded - {expected_feature_count} features")
else:
    model = None
    feature_names = []
    expected_feature_count = 0
    print("Model or Feature List Not Found!")

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Phishing Detector API Running"})

@app.route("/api/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        print("Received Data:", data)

        if not data or "url" not in data:
            return jsonify({"error": "Invalid input, 'url' missing"}), 400

        url = data["url"]
        print(f"URL Received: {url}")

        # Extract Features
        feature_values = extract_features(url)
        if feature_values is None:
            return jsonify({"error": "Feature extraction failed"}), 500

        feature_array = np.array(feature_values).reshape(1, -1)
        zero_count = feature_values.count(0)
        
        print("Feature Array:", feature_array)
        print(f"Model expects {expected_feature_count} features, got {len(feature_values)}")
        

        if len(feature_values) != expected_feature_count:
            return jsonify({"error": f"Feature count mismatch: Expected {expected_feature_count}, got {len(feature_values)}"}), 400

        # Predict using Model ( ONLY FOR DEBUGGING )
        prediction = model.predict(feature_array)[0]  # Directly get 0 or 1
        prediction_prob = model.predict_proba(feature_array)[0]  # Get probability
        
        if zero_count >= 32:
        
            return jsonify({"status": "Legitimate", "message": "✅This website is Legitimate.✅"})

        if prediction == 1:
            return jsonify({"status": "Phishing", "message": "❌This website is a Phishing site!❌"})
        else:
            return jsonify({"status": "Legitimate", "message": "This website is Legitimate."})

    except Exception as e:
        print(f"Exception Occurred: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Feature Extraction Function (Fixed for Correct Order)
def extract_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    # Feature Extraction in Correct Order
    features = {
        "qty_dot_url": url.count('.'),
        "qty_hyphen_url": url.count('-'),
        "qty_underline_url": url.count('_'),
        "qty_slash_url": url.count('/'),
        "qty_questionmark_url": url.count('?'),
        "qty_equal_url": url.count('='),
        "qty_at_url": url.count('@'),
        "qty_and_url": url.count('&'),
        "qty_exclamation_url": url.count('!'),
        "qty_space_url": url.count(' '),
        "qty_tilde_url": url.count('~'),
        "qty_comma_url": url.count(','),
        "qty_plus_url": url.count('+'),
        "qty_asterisk_url": url.count('*'),
        "qty_hashtag_url": url.count('#'),
        "qty_dollar_url": url.count('$'),
        "qty_percent_url": url.count('%'),
        "qty_tld_url": len(parsed_url.path.split('.')) - 1,
        "length_url": len(url),
        "qty_dot_domain": domain.count('.'),
        "qty_hyphen_domain": domain.count('-'),
        "qty_underline_domain": domain.count('_'),
        "qty_slash_domain": domain.count('/'),
        "qty_questionmark_domain": domain.count('?'),
        "qty_equal_domain": domain.count('='),
        "qty_at_domain": domain.count('@'),
        "qty_and_domain": domain.count('&'),
        "qty_exclamation_domain": domain.count('!'),
        "qty_space_domain": domain.count(' '),
        "qty_tilde_domain": domain.count('~'),
        "qty_comma_domain": domain.count(','),
        "qty_plus_domain": domain.count('+'),
        "qty_asterisk_domain": domain.count('*'),
        "qty_hashtag_domain": domain.count('#'),
        "qty_dollar_domain": domain.count('$'),
        "qty_percent_domain": domain.count('%'),
        "qty_vowels_domain": sum(1 for c in domain if c in "aeiouAEIOU"),
    }

    # Reorder Features as per `feature_names.pkl`
    try:
        feature_values = [features[feat] for feat in feature_names]
    except KeyError as e:
        print(f"Feature missing in extraction: {e}")
        return None

    print(f"Extracted Features ({len(feature_values)}):", feature_values)
    return feature_values

if __name__ == "__main__":
    app.run(debug=True, host="localhost", port=5000)
