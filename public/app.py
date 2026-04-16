from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

app = Flask(__name__)
CORS(app)

model = joblib.load("phishing_model.joblib")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        features = data["features"]

        prediction = model.predict([features])[0]

        proba = model.predict_proba([features])[0]

        # 🔥 SAFE HANDLING (fixes your crash)
        if len(proba) > 1:
            probability = proba[1]
        else:
            probability = proba[0]

        return jsonify({
            "prediction": int(prediction),
            "confidence": float(probability)
        })

    except Exception as e:
        print("ERROR:", e)
        return jsonify({
            "prediction": 0,
            "confidence": 0,
            "error": str(e)
        })

if __name__ == "__main__":
    app.run(debug=True)