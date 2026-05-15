import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import Dataset, DataLoader
import torch.nn as nn
import model

from variable import columns, LoadData, device

# 数据归一化
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


def pre():

    df = pd.read_csv('D:\\bishe\\netdata\\fin_data.csv', header=None, low_memory=False)

    df.columns = columns

    cat_col = df.drop(columns=['Label'])


    # 数据标准化
    df = encode_numeric_zscore(df, cat_col)

    # 数据归一化
    df = encode_numeric_range(df, cat_col)

    # 数据数值化
    df = Numerical_Encoding(df, df.Label)

    X = df.drop(columns=['Label'])
    y = df['Label']

    test_data = LoadData(X, y)

    # 加载数据
    test_dataloader = DataLoader(test_data, batch_size=1, drop_last=False)

    # 加载模型
    CNN_model = model.CNN()
    CNN_model.to(device=device)
    CNN_model.load_state_dict(torch.load("D:\\bishe\\train_model/CNN.pth"))

    classes_map = ['BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
                   'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan',
                   'SSH-Patator', 'Web Attack � Brute Force', 'Web Attack � Sql Injection',
                   'Web Attack � XSS']

    y_pred_list = []
#    y_pred_list.append('Label')
    CNN_model.eval()
    with torch.no_grad():
        iter = 0
        for X, y in test_dataloader:
            X = X.to(device).to(torch.float32)
            X = X.reshape(1, 1, 78)
            X = X.reshape(1, 1, 6, 13)
            y_pred = CNN_model(X)
            iter += 1

            for item in y_pred:
#                print("item:{}".format(item))
#                print("-----------------\n预测:{}\n".format(classes_map[torch.argmax(item)]))
                y_pred_list.append(classes_map[torch.argmax(item)])
        y_pred_array = np.array(y_pred_list)
    fin = pd.read_csv('D:\\bishe\\netdata\\captured_traffic.pcap_Flow.csv', encoding='GBK')

    # 替换 'column_to_replace' 列的数据
    fin[fin.columns[-1]] = y_pred_array

    # 将修改后的 DataFrame 保存回 CSV 文件
    fin.to_csv('D:\\bishe\\netdata\\captured_traffic.pcap_Flow.csv', index=False)
#    print(len(y_pred_array))
 #   print(y_pred_array)
#pre()