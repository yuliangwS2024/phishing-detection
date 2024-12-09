import pandas as pd
from urllib.parse import urlparse, parse_qs
import re
from transformers import AutoTokenizer, AutoModel
import torch
import pandas as pd
from tqdm import tqdm


def extract_url_features(url):
    """
    Extract features from a given URL.
    Args:
        url (str): The URL to extract features from.
    Returns:
        dict: Extracted features as a dictionary.
    """
    try:
        # Parse URL components
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query

        # Domain features
        domain_length = len(domain)
        subdomain_count = domain.count('.') - 1
        trusted_domain = 1 if 'google.com' in domain else 0

        # Path features
        path_depth = path.count('/')
        path_tokens = re.split(r'[/.]', path)
        special_characters = sum(1 for char in path if char in '-_%')

        # Query features
        query_params = parse_qs(query)
        query_param_count = len(query_params)
        query_key_entropy = sum(len(k) for k in query_params) / (query_param_count or 1)

        return {
            'domain_length': domain_length,
            'subdomain_count': subdomain_count,
            'trusted_domain': trusted_domain,
            'path_depth': path_depth,
            'path_token_count': len(path_tokens),
            'special_characters': special_characters,
            'query_param_count': query_param_count,
            'query_key_entropy': query_key_entropy
        }
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return {
            'domain_length': 0,
            'subdomain_count': 0,
            'trusted_domain': 0,
            'path_depth': 0,
            'path_token_count': 0,
            'special_characters': 0,
            'query_param_count': 0,
            'query_key_entropy': 0
        }


def add_url_features_to_df(df):
    """
    Add URL-specific features extracted by extract_url_features to an existing DataFrame.
    Args:
        df (pd.DataFrame): The original DataFrame with process_url features.
    Returns:
        pd.DataFrame: Updated DataFrame with additional URL features.
    """
    # 检查 df 是否包含 "url" 列
    if "url" not in df.columns:
        raise ValueError("The DataFrame must contain a 'url' column.")

    # 提取每个 URL 的特征
    url_features_list = []
    for url in df['url']:
        url_features = extract_url_features(url)  # 调用 extract_url_features 函数
        url_features_list.append(url_features)

    # 将 URL 特征转化为 DataFrame
    url_features_df = pd.DataFrame(url_features_list)

    # 合并原始 DataFrame 和 URL 特征 DataFrame
    updated_df = pd.concat([df, url_features_df], axis=1)
    return updated_df



def split_server_version(version):
    """
    Splits the server version string into major, minor, and patch numbers.
    Args:
        version (str): Server version string (e.g., "1.18.0").
    Returns:
        tuple: (major, minor, patch) as integers, or -1 for missing components.
    """
    if pd.isna(version) or version == '' or version == '.' or version == '..':
        return -1, -1, -1
    parts = version.split('.')
    major = int(parts[0]) if len(parts) > 0 else -1
    minor = int(parts[1]) if len(parts) > 1 else -1
    patch = int(parts[2]) if len(parts) > 2 else -1
    return major, minor, patch


def preprocess_server_version(df):
    """
    Splits the `server_version` column into `server_major`, `server_minor`, and `server_patch`.
    Drops the original `server_version` column.
    Args:
        df (pd.DataFrame): Input DataFrame with a `server_version` column.
    Returns:
        pd.DataFrame: Updated DataFrame with new columns and without `server_version`.
    """
    # Split `server_version` and create new columns
    df[['server_major', 'server_minor', 'server_patch']] = df['server_version'].apply(
        lambda x: pd.Series(split_server_version(x))
    )
    # Drop the original `server_version` column
    df = df.drop(columns=['server_version'])
    return df


# 定义 URL 分词函数
def tokenize_url(url):
    tokens = re.split(r'[/.?&=]', url)
    tokens = [token for token in tokens if token]
    return ' '.join(tokens)



# 配置
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"  # 选择适合的预训练模型
DEVICE = torch.device("cpu")

# 加载模型和分词器
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME).to(DEVICE)

def extract_llm_features(texts):
    """
    使用预训练 LLM 提取特征
    :param texts: 文本列表 (URLs)
    :return: 嵌套列表形式的嵌入
    """
    embeddings = []
    for text in tqdm(texts, desc="Extracting LLM features"):
        try:
            # Tokenize 输入文本
            inputs = tokenizer(text, return_tensors="pt", truncation=True, padding="max_length", max_length=128).to(DEVICE)
            with torch.no_grad():
                outputs = model(**inputs)
                # 取池化后的嵌入
                embedding = outputs.last_hidden_state.mean(dim=1).squeeze().cpu().numpy().tolist()
                embeddings.append(embedding)
        except Exception as e:
            print(f"Error processing text: {text}. Error: {e}")
            embeddings.append([0] * 384)  # 如果出错，用零向量填充，假设嵌入维度为 384
    return embeddings

def add_llm_features_to_df(input_df):
    """
    添加 LLM 特征到原始 DataFrame
    :param input_df: 原始 DataFrame
    :return: 添加了 LLM 特征的新 DataFrame
    """
    # 提取 URL 列
    urls = input_df['url'].tolist()

    # 生成 LLM 嵌入
    print("Generating LLM features for URLs...")
    llm_features = extract_llm_features(urls)

    # 创建 LLM 特征 DataFrame
    if isinstance(llm_features, list) and all(isinstance(row, list) for row in llm_features):
        num_features = len(llm_features[0])
        llm_features_df = pd.DataFrame(llm_features, columns=[f"llm_feature_{i}" for i in range(num_features)])
    else:
        print("Error: LLM features are not in the expected format.")
        return input_df

    # 合并原始 DataFrame 和 LLM 特征
    updated_df = pd.concat([input_df, llm_features_df], axis=1)
    return updated_df
