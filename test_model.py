import pickle

# Model file read kar
with open("phishing_detector.pkl", "rb") as f:
    data = pickle.load(f)

# Model ka type print karo
print("📌 Model Type:", type(data))
