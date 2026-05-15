import os
import sys

import numpy as np
import pandas as pd
import onnxruntime as ort
from sklearn.preprocessing import LabelEncoder

current_file_path = os.path.dirname(sys.argv[0])
print(current_file_path)
columns = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
]
def encode_numeric_range(df, names, normalized_low=0, normalized_high=1,
                         data_low=None, data_high=None):
    for name in names:
        if data_low is None:
            data_low = min(df[name])
            data_high = max(df[name])

        df[name] = ((df[name] - data_low) / (data_high - data_low)) \
                   * (normalized_high - normalized_low) + normalized_low
    return df


# 数据标准化
def encode_numeric_zscore(df, names, mean=None, sd=None):
    for name in names:
        if mean is None:
            mean = df[name].mean()

        if sd is None:
            sd = df[name].std()

        df[name] = (df[name] - mean) / sd
    return df


# 数据数值化
def Numerical_Encoding(df, label):
    labels = pd.DataFrame(label)

    label_encoder = LabelEncoder()
    enc_label = labels.apply(label_encoder.fit_transform)

    df.Label = enc_label
    return df



def load_data(pre_pth, columns):
    df = pd.read_csv(pre_pth, header=None, low_memory=False)
    df.columns = columns

    cat_col = df.drop(columns=['Label'])

    # 数据标准化
    df = encode_numeric_zscore(df, cat_col.columns)

    # 数据归一化
    df = encode_numeric_range(df, cat_col.columns)

    # 数据数值化
    df = Numerical_Encoding(df, df.Label)

    X = df.drop(columns=['Label'])
    y = df['Label']
    return X, y


def pre():
    pre_pth = current_file_path + "\\fin_data.csv"
    pre_columns = columns  # 根据你的数据集调整列名
    X, y = load_data(pre_pth, pre_columns)

    # 转换为 numpy 数组
    X_np = X.values.astype(np.float32)
    y_np = y.values.astype(np.float32)

    # 加载 ONNX 模型
    onnx_path = "./train_model/CNN.onnx"
    ort_session = ort.InferenceSession(onnx_path)

    classes_map = ['BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
                   'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan',
                   'SSH-Patator', 'Web Attack – Brute Force', 'Web Attack – Sql Injection',
                   'Web Attack – XSS']

    y_pred_list = []
    for X_single in X_np:
        X_single = X_single.reshape(1, 1, 6, 13)
        ort_inputs = {ort_session.get_inputs()[0].name: X_single}
        ort_outs = ort_session.run(None, ort_inputs)
        y_pred = ort_outs[0]

        y_pred_list.append(classes_map[np.argmax(y_pred)])

    y_pred_array = np.array(y_pred_list)

    fin_pth = current_file_path + "\\captured_traffic.pcap_Flow.csv"
    fin = pd.read_csv(fin_pth, encoding='GBK')

    # 替换最后一列的数据
    fin[fin.columns[-1]] = y_pred_array

    # 将修改后的 DataFrame 保存回 CSV 文件
    fin.to_csv(fin_pth, index=False)

pre()