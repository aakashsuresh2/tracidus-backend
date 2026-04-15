import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Load the trained model
model = joblib.load('phishing_model.joblib')

# Define the input type for the model
# The number 4 in FloatTensorType([None, 4]) matches the 4 features you created.
initial_type = [('float_input', FloatTensorType([None, 4]))]

# Convert the model to ONNX format
onnx_model = convert_sklearn(model, initial_types=initial_type)

# Save the ONNX model to a file
with open("phishing_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("Model conversion complete. File 'phishing_model.onnx' saved.")