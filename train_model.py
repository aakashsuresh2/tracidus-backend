import pandas as pd

print("🚀 SCRIPT STARTED")

df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

print("✅ FILE LOADED")

print("========== DATASET COLUMNS ==========")
for i, col in enumerate(df.columns):
    print(i, "->", col)
print("====================================")

input("⛔ Press Enter to continue...")