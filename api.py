import pickle

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

from feature_extraction import process_url
from preproess import add_llm_features_to_df, add_url_features_to_df, \
    preprocess_server_version, \
    tokenize_url

# 加载模型
with open("best_model_LightGBM_handcrafted_tfidf_llm.pkl", "rb") as file:
    model_data = pickle.load(file)

tuned_model = model_data["model"]
print("Model loaded successfully!")



from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 示例数据存储
data_store = {
    "urls": []
}


# 首页路由
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to the URL Prediction API!"}), 200


@app.route("/predict", methods=["POST"])
def predict():
    try:
        # 从请求中获取 URL
        request_data = request.json
        url = request_data.get("url")

        if not url:
            return jsonify({"error": "Missing 'url' parameter"}), 400

        # preprocess url into features
        features = process_url(url, -1)
        feature_names = [
            "url", "server_label", "server_version", "request_url_percentage",
            "count_domain_occurrences", "TTL", "ip_address_count", "TXT_record",
            "issuer", "certificate_age", "domain_registeration_length",
            "abnormal_url", "age_of_domain"
        ]
        df = pd.DataFrame([features], columns=feature_names)
        # extract url features
        df = add_url_features_to_df(df)
        # process server version
        df = preprocess_server_version(df)
        # add nlp feature
        df['url_tokens'] = df['url'].apply(tokenize_url)
        tfidf_vectorizer = TfidfVectorizer(max_features=1000)
        tfidf_features = tfidf_vectorizer.fit_transform(
            df['url_tokens']).toarray()
        tfidf_features_df = pd.DataFrame(tfidf_features,
                                         columns=tfidf_vectorizer.get_feature_names_out())
        df = pd.concat([df, tfidf_features_df], axis=1)
        df = df.drop(columns=['url_tokens'])
        df = add_llm_features_to_df(df)
        df = df.drop(columns=["url"])
        df = df.drop(columns=["issuer"])
        df = df.drop(columns=["label"])

        prediction = model_data["model"].predict(df)[0]
        probability = model_data["model"].predict_proba(df)[0]


        logging.info(
            f"Prediction for URL {url}: {prediction}, Probability: {probability}")
        return jsonify({
            "url": url,
            "prediction": prediction,
            "probability": probability
        }), 200
    except Exception as e:
        logging.error(f"Error predicting URL: {str(e)}")
        return jsonify({"error": str(e)}), 500


# 404 错误处理
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404


# 全局错误处理
@app.errorhandler(Exception)
def handle_exception(error):
    logging.error(f"Unhandled exception: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True)
