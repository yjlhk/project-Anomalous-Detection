import os
import sys
import pandas as pd
import logging  # 添加日志模块
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtWidgets import QWidget, QPushButton, QVBoxLayout, QLabel, QHBoxLayout, QApplication, \
    QTableWidget, QTableWidgetItem, QLineEdit, QMessageBox
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

from data_preprocess.get_feature import get_feature
from data_preprocess.process_feature import process_feature
from predict import pre

# 设置日志记录的级别和格式
#logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

class CaptureThread(QThread):
    finished_signal = pyqtSignal(bool)

    def __init__(self, num_packets):
        super().__init__()
        self.num_packets = num_packets
        self.worker = FeatureWorker()  # 在构造函数中创建 FeatureWorker 对象

    def run(self):
        filterstr = "tcp||udp"
#        logging.info("Start capturing packets...")
        if os.path.exists("D:\\bishe\\netdata\\captured_traffic.pcap"):
            os.remove("D:\\bishe\\netdata\\captured_traffic.pcap")
#        logging.info("remove finished!!")
        B = sniff(iface="WLAN", count=self.num_packets, filter=filterstr, prn=self.pack_callback)
#        logging.info("Capture finished.")
        self.get_and_process_features()

    def pack_callback(self, packet):
#        logging.debug("Received packet: %s", packet.summary())
        wrpcap("D:\\bishe\\netdata\\captured_traffic.pcap", packet, append=True)

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
#        logging.info("get_feature已完成，开始process_feature")
        process_feature()
#        logging.info("process_feature已完成")
        self.finished_signal.emit(True)
       # QTimer.singleShot(0, self.process_feature)  # 延迟执行 process_feature



class WorkerThread(QThread):
    update_signal = pyqtSignal(list)

    def run(self):
#        logging.info("Start analyzing captured data...")
        pre()  # 调用预测函数
#        logging.info("pre finished!!...")
        fd = pd.read_csv('D:\\bishe\\netdata\\captured_traffic.pcap_Flow.csv', encoding='GBK')
#        logging.info("fd finished!!...")
        data = fd[['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Label']].values.tolist()
        self.update_signal.emit(data)
#        logging.info("Analysis finished.")


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
