import pandas as pd
import numpy as np
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import nltk
from nltk.corpus import stopwords

# Download required NLTK data (if not already downloaded)
nltk.download('punkt')
nltk.download('stopwords')

# Define a simple preprocessor: convert text to lowercase
def preprocess_text(text):
    return text.lower()

# Load the phishing email dataset
# Make sure the file "phishing_email.csv" is in your current directory.
df = pd.read_csv("phishing_email.csv")

# Display first few rows for verification
print("Dataset preview:")
print(df.head())

# Use TfidfVectorizer to transform the email text into numerical features.
# It will automatically tokenize the text (using the preprocessor we defined) and remove stopwords.
vectorizer = TfidfVectorizer(preprocessor=preprocess_text,
                             stop_words=stopwords.words('english'),
                             max_features=5000)

X = vectorizer.fit_transform(df['text_combined'].astype(str))
y = df['label']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y,
                                                    test_size=0.2,
                                                    random_state=42)

# Train a Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")

# Save the trained model and the vectorizer for future use
with open("phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("✅ Model and vectorizer saved as phishing_model.pkl and vectorizer.pkl")

