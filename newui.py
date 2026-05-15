# -*- coding: utf-8 -*-
from torch.utils.data import Dataset
import os
import subprocess
import sys
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtWidgets import QWidget, QPushButton, QVBoxLayout, QLabel, QHBoxLayout, QApplication, \
    QTableWidget, QTableWidgetItem, QLineEdit, QMessageBox
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import numpy as np
import pandas as pd

from torch import nn, tensor, load, no_grad, float32, argmax
from sklearn.preprocessing import LabelEncoder
from torch.utils.data import DataLoader

device = 'cpu'
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

class LoadData(Dataset):
    def __init__(self, X, y):
        self.X = X
        self.y = y

    def __len__(self):
        return len(self.X)

    def __getitem__(self, index):
        X = tensor(self.X.iloc[index])
        y = tensor(self.y.iloc[index])
        return X, y
class CNN(nn.Module):
    def __init__(self, num_class=15):
        super(CNN, self).__init__()
        self.avg_kernel_size = 4
        self.i_size = 16
        self.num_class = num_class
        self.input_space = None
        self.input_size = (self.i_size, self.i_size, 1)

        self.conv1 = nn.Sequential(
            nn.Conv2d(1, 16, kernel_size=3, stride=1, dilation=1, padding=1, bias=True),
            nn.BatchNorm2d(16, eps=1e-05, momentum=0.9, affine=True),
            nn.ReLU(),
        )

        self.conv2 = nn.Sequential(
            nn.Conv2d(16, 32, kernel_size=3, stride=2, dilation=1, padding=1, bias=True),
            nn.BatchNorm2d(32, eps=1e-05, momentum=0.9, affine=True),
            nn.ReLU(),
        )

        self.conv3 = nn.Sequential(
            nn.Conv2d(32, 64, kernel_size=3, stride=1, dilation=1, padding=1, bias=True),
            nn.BatchNorm2d(64, eps=1e-05, momentum=0.9, affine=True),
            nn.ReLU(),
        )

        self.conv4 = nn.Sequential(
            nn.Conv2d(64, 128, kernel_size=3, stride=2, dilation=1, padding=1, bias=True),
            nn.BatchNorm2d(128, eps=1e-05, momentum=0.9, affine=True),
            nn.ReLU(),
        )

        self.avg_pool = nn.AvgPool2d(kernel_size=2, stride=1, ceil_mode=False)
        self.fc0 = nn.Sequential(
            nn.BatchNorm1d(384),
            nn.Dropout(0.5),
            nn.Linear(384, self.num_class, bias=True),
        )

    def features(self, input_data):
        x = self.conv1(input_data)
        x = self.conv2(x)
        x = self.conv3(x)
        x = self.conv4(x)
        return x

    def logits(self, input_data):
        x = self.avg_pool(input_data)
        out = x.view(x.size(0), -1)
        x = self.fc0(out)
        return x

    def forward(self, input_data):
        x = self.features(input_data)
        x = self.logits(x)
        return x

#logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

current_file_path = os.path.dirname(os.path.abspath(__file__))
def process_feature():
    columns = [
        'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Destination Port', 'Protocol', 'Timestamp',
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
        'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
        'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
        'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
        'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
        'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
        'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
        'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
        'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std',
        'Idle Max', 'Idle Min', 'Label'
    ]
    to_columns = [
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
#    logging.info("开始读取Flow")
#    logging.info("当前路径：{}".format(current_file_path))
    pro_fea_pth = current_file_path + "\\captured_traffic.pcap_Flow.csv"
    df = pd.read_csv(pro_fea_pth, header=None, low_memory=False, encoding='GBK')
#    logging.info("读取成功Flow")
    to_df = pd.DataFrame()
    i = 0
    for df_colum in to_columns:
        if df_colum in columns:
            to_df[i] = df[columns.index(df_colum)]
            i = i + 1
    to_pth = current_file_path + '\\fin_data.csv'
    to_df = to_df.drop([0])
    to_df.to_csv(to_pth, index=False, header=False)

def get_feature():
    pth = os.path.abspath(__file__)
    print(pth)
    input_file = os.path.dirname(pth) + "\\captured_traffic.pcap"
    output_path = os.path.dirname(pth) + "\\"

    if not os.path.exists(output_path):
        os.makedirs(output_path)
    os.chdir(r"cicflowmeter-4\\CICFlowMeter-4.0\\bin")
    command = ['cfm.bat', f"{input_file}", f"{output_path}"]
    subprocess.call(command)



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
    pre_pth = current_file_path + "\\fin_data.csv"
    df = pd.read_csv(pre_pth, header=None, low_memory=False)

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
    CNN_model = CNN()
    CNN_model.to(device=device)
    CNN_pth = current_file_path + "\\train_model\\CNN.pth"
    CNN_model.load_state_dict(load(CNN_pth))

    classes_map = ['BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk', 'DoS Slowhttptest',
                   'DoS slowloris', 'FTP-Patator', 'Heartbleed', 'Infiltration', 'PortScan',
                   'SSH-Patator', 'Web Attack � Brute Force', 'Web Attack � Sql Injection',
                   'Web Attack � XSS']

    y_pred_list = []
    CNN_model.eval()
    with no_grad():
        iter = 0
        for X, y in test_dataloader:
            X = X.to(device).to(float32)
            X = X.reshape(1, 1, 78)
            X = X.reshape(1, 1, 6, 13)
            y_pred = CNN_model(X)
            iter += 1

            for item in y_pred:
                y_pred_list.append(classes_map[argmax(item)])
        y_pred_array = np.array(y_pred_list)
    fin_pth = current_file_path + "\\captured_traffic.pcap_Flow.csv"
    fin = pd.read_csv(fin_pth, encoding='GBK')

    # 替换 'column_to_replace' 列的数据
    fin[fin.columns[-1]] = y_pred_array

    # 将修改后的 DataFrame 保存回 CSV 文件
    fin.to_csv(fin_pth, index=False)




class CaptureThread(QThread):
    finished_signal = pyqtSignal(bool)
    def __init__(self, num_packets):
        super().__init__()
        self.num_packets = num_packets
        self.worker = FeatureWorker()  # 在构造函数中创建 FeatureWorker 对象

    def run(self):
        filterstr = "tcp||udp"
#        logging.info("Start capturing packets...")
        if os.path.exists("captured_traffic.pcap"):
            os.remove("captured_traffic.pcap")
#        logging.info("remove finished!!")
        B = sniff(iface="WLAN", count=self.num_packets, filter=filterstr, prn=self.pack_callback)
#        logging.info("Capture finished.")
        self.get_and_process_features()

    def pack_callback(self, packet):
#        logging.debug("Received packet: %s", packet.summary())
        wrpcap("captured_traffic.pcap", packet, append=True)

    def get_and_process_features(self):
#        logging.info("Start getting and processing features...")
        # 将特征处理过程放入后台线程中执行
        self.worker.finished_signal.connect(self.feature_processing_finished)
        self.worker.start()  # 启动 FeatureWorker 线程

    def feature_processing_finished(self, flag):
#        logging.info("Feature processing finished.")
        self.finished_signal.emit(True)

class FeatureWorker(QThread):
    finished_signal = pyqtSignal(bool)

    def run(self):
#        logging.info("进入FW线程")
        get_feature()
 #       logging.info("get_feature已完成，开始process_feature")
        process_feature()
 #       logging.info("process_feature已完成")
        self.finished_signal.emit(True)
        #QTimer.singleShot(0, self.process_feature)  # 延迟执行 process_feature



class WorkerThread(QThread):
    update_signal = pyqtSignal(list)

    def run(self):
 #       logging.info("Start analyzing captured data...")
        pre()  # 调用预测函数
#        logging.info("pre finished!!...")
        fd_pth = current_file_path + "\\captured_traffic.pcap_Flow.csv"
        fd = pd.read_csv(fd_pth, encoding='GBK')
 #       logging.info("fd finished!!...")
        data = fd[['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Label']].values.tolist()
        self.update_signal.emit(data)
 #       logging.info("Analysis finished.")


class MyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.msg_history = list()

    def init_ui(self):
        self.resize(1000, 800)
        container = QVBoxLayout()

        self.setWindowTitle("异常流量检测")

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Src IP", "Src Port", "Dst IP", "Dst Port", "Class"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)  # 设置表格为不可编辑

        container.addWidget(self.table)

        h_layout = QHBoxLayout()
        txt = QLabel("捕获报文个数:")
        self.num = QLineEdit()
        btn_0 = QPushButton('开始捕获', self)
        btn_0.clicked.connect(self.cap)
        btn = QPushButton("开始检测", self)
        btn.clicked.connect(self.check)
        h_layout.addStretch(1)
        h_layout.addWidget(txt)
        h_layout.addWidget(self.num)
        h_layout.addWidget(btn_0)
        h_layout.addStretch(1)
        h_layout.addWidget(btn)
        h_layout.addStretch(1)

        container.addLayout(h_layout)

        self.setLayout(container)

    def update_table(self, data):
        self.table.setRowCount(len(data))
        for i, row in enumerate(data):
            for j, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                self.table.setItem(i, j, item)

    def check(self):
        self.worker_thread = WorkerThread()
        self.worker_thread.update_signal.connect(self.update_table)
        self.worker_thread.start()

    def cap(self):
        num_packets = int(self.num.text())
        self.capture_thread = CaptureThread(num_packets)
        self.capture_thread.finished_signal.connect(self.capture_finished)
        self.capture_thread.start()

    def capture_finished(self, flag):
        if flag:
            QMessageBox.information(self, "捕获完成", "成功捕获了{}个数据包".format(self.capture_thread.num_packets))
            #print("已捕获{}个数据包".format(self.capture_thread.num_packets))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MyWindow()
    w.show()
    sys.exit(app.exec_())
