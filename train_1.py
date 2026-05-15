import os

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import Dataset, DataLoader
import torch.nn as nn

import model

df = pd.read_csv('data\expendData\\totall_extend.csv', header=None, low_memory=False)
last_column_index = df.shape[1] - 1
# print(df[last_column_index].value_counts())
df.columns = [
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
df.dropna(inplace=True, axis=0)
# 得到标签列索引

all_col = df.columns
print(all_col)
cat_col = df.drop(columns=['Label'])


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


# 数据标准化
df = encode_numeric_zscore(df, cat_col)

# 数据归一化
df = encode_numeric_range(df, cat_col)

# 数据数值化
df = Numerical_Encoding(df, df.Label)

# 异常清除
invalid_mask = np.isnan(df) | np.isinf(df)
valid_rows = ~np.any(invalid_mask, axis=1)

# 仅保留有效行
df = df[valid_rows]
X = df.drop(columns=['Label'])
y = df['Label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=50)


class LoadData(Dataset):
    def __init__(self, X, y):
        self.X = X
        self.y = y

    def __len__(self):
        return len(self.X)

    def __getitem__(self, index):
        X = torch.tensor(self.X.iloc[index])
        y = torch.tensor(self.y.iloc[index])
        return X, y


# dataset
train_data = LoadData(X_train, y_train)
test_data = LoadData(X_test, y_test)

X_dimension = len(X_train.columns)
y_dimension = len(y_train.value_counts())
print(f"X的维度：{X_dimension}")
print(f"y的维度：{y_dimension}")

# 加载数据
batch_size = 128
train_dataloader = DataLoader(train_data, batch_size=batch_size, drop_last=True)
test_dataloader = DataLoader(test_data, batch_size=batch_size, drop_last=True)

# 使用cuda进行GPU加速，如果无可加速显卡，则使用cpu
device = 'cuda:0' if torch.cuda.is_available() else 'cpu'



def test(model, loss_fn):
    positive = 0
    negative = 0
    with torch.no_grad():
        iter = 0
        loss_sum = 0
        for X, y in test_dataloader:
            X, y = X.to(device).to(torch.float32), y.to(device).to(torch.float32)
            X = X.reshape(X.shape[0], 1, X_dimension)
            X = X.reshape(128, 1, 6, 13)
            y_pred = model(X)
            loss = loss_fn(y_pred, y.long())
            loss_sum += loss.item()
            iter += 1
            for item in zip(y_pred, y):
                if torch.argmax(item[0]) == item[1]:
                    positive += 1
                else:
                    negative += 1
    acc = positive / (positive + negative)
    avg_loss = loss_sum / iter
    print("Accuracy:", acc)
    print("Average Loss:", avg_loss)
    return acc


# 训练函数
def train(model, optimizer, loss_fn, epochs, target, str):
    losses = []
    iter = 0

    for epoch in range(epochs):
        print(f"epoch {epoch + 1}\n-----------------")
        for i, (X, y) in enumerate(train_dataloader):
            X, y = X.to(device).to(torch.float32), y.to(device).to(torch.float32)
            X = X.reshape(X.shape[0], 1, X_dimension)
            X = X.reshape(128, 1, 6, 13)
            y_pred = model(X)
            loss = loss_fn(y_pred, y.long())

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            if i % 100 == 0:
                print("模型:{}".format(str))
                print(f"loss: {loss.item()}\t[{(i + 1) * len(X)}/{len(train_data)}]")

                iter += 1
                losses.append(loss.item())
        model.eval()
        test_acc = test(model, loss_fn)
        if(test_acc > target):
            target = test_acc
            pth = './train_model/' + str + '.pth'
            torch.save(model.state_dict(), pth)

    return losses, iter

CNN_model = model.CNN()
CNN_model.to(device=device)
AlexNet8 = model.AlexNet8()
AlexNet8.to(device=device)
VGG16 = model.VGG16()
VGG16.to(device=device)

model_list = []
model_list.append(CNN_model)
model_list.append(AlexNet8)
model_list.append(VGG16)
target = 0.0

# 训练模型

loss_fn = nn.CrossEntropyLoss()
learning_rate_list = [0.01, 0.001, 0.0001]
target = [0, 0, 0.91]

if os.path.exists('./train_model/CNN.pth'):
    print("存在已训练CNN模型，正在载入-----")
    CNN_model.load_state_dict(torch.load('./train_model/CNN.pth'))
    print("正在获取已训练CNN模型准确度-----")
    CNN_model.eval()
    target[0] = test(CNN_model, loss_fn)
    print("已有CNN模型准确度：{}".format(target[0]))
else:
    print("未找到训练模型,将重新创建----\n")

if os.path.exists('./train_model/AlexNet8.pth'):
    print("存在已训练AlexNet8模型，正在载入-----")
    AlexNet8.load_state_dict(torch.load('./train_model/AlexNet8.pth'))
    print("正在获取已训练AlexNet8模型准确度-----")
    AlexNet8.eval()
    target[1] = test(AlexNet8, loss_fn)
    print("已有AlexNet8模型准确度：{}".format(target[1]))
else:
    print("未找到训练AlexNet8模型,将重新创建----\n")


if os.path.exists('./train_model/VGG16.pth'):
    print("存在已训练VGG16模型，正在载入-----")
    VGG16.load_state_dict(torch.load('./train_model/VGG16.pth'))
    print("正在获取已训练VGG16模型准确度-----")
    VGG16.eval()
    target[2] = test(VGG16, loss_fn)
    print("已有VGG16模型准确度：{}".format(target[2]))
else:
    print("未找到VGG16训练模型,将重新创建----\n")

str_list = []
str_list.append('CNN')
str_list.append('AlexNet8')
str_list.append('VGG16')
for i in range(3):
    if i == 0 or i == 1:
        continue
    train_model = model_list[i]
    train_model.train()
    for j in range(3):
        print("开始训练：")
        optimizer = torch.optim.SGD(train_model.parameters(), lr=learning_rate_list[j])
        epoch = 1
        losses, iter = train(train_model, optimizer, loss_fn, epochs=epoch, target=target[i], str=str_list[i])
        print("********losses:{}\niter:{}".format(losses, iter))

