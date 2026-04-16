import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# LOAD DATASET
df = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv')

# TARGET
df['is_phishing'] = df['label'].apply(lambda x: 1 if x == 'phishing' else 0)

# 🔥 SELECT ONLY URL-BASED FEATURES
feature_columns = [
    'URLLength',
    'DomainLength',
    'IsDomainIP',
    'NoOfSubDomain',
    'NoOfLettersInURL',
    'LetterRatioInURL',
    'NoOfDegitsInURL',
    'DegitRatioInURL',
    'NoOfEqualsInURL',
    'NoOfQMarkInURL',
    'NoOfAmpersandInURL',
    'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL',
    'IsHTTPS'
]

print("Using features:", feature_columns)

# CLEAN DATA
df[feature_columns] = df[feature_columns].apply(pd.to_numeric, errors='coerce').fillna(0)

X = df[feature_columns]
y = df['is_phishing']

# SPLIT
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# TRAIN
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ACCURACY
print("Accuracy:", model.score(X_test, y_test))

# SAVE
joblib.dump(model, 'phishing_model.joblib')

print("✅ Model ready")