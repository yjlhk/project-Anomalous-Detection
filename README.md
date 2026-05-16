# 异常流量检测系统 | Abnormal Traffic Detection System

## 📜 项目声明 | Project Declaration

- **项目名称** | **Project Name**: 异常流量检测系统 (Abnormal Traffic Detection System)
- **项目作者** | **Project Author**: Jiale Yang、Yan Lin
- **项目单位** | **Project Institution**: 暨南大学网络空间安全学院（Jinan University School of Cyberspace Security）

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-1.x-orange.svg)](https://pytorch.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 项目简介 | Project Overview

本项目是一个基于深度学习的网络异常流量检测系统，能够实时捕获网络数据包，提取流量特征，并使用训练好的深度学习模型对网络流量进行分类和识别，检测包括DDoS攻击、Web攻击等多种网络威胁。

This project is a deep learning-based network abnormal traffic detection system that can capture network packets in real-time, extract traffic features, and use trained deep learning models to classify and identify network traffic, detecting various network threats including DDoS attacks, web attacks, and more.

## ✨ 主要功能 | Key Features

- 🔄 **实时流量捕获** | **Real-time Traffic Capture**: 基于Scapy实现网络数据包的实时捕获
- 📊 **特征提取** | **Feature Extraction**: 使用CICFlowMeter提取80+网络流量特征
- 🤖 **多模型支持** | **Multi-model Support**: 支持CNN、AlexNet、VGG16三种深度学习模型
- 🎯 **流量分类** | **Traffic Classification**: 可识别15种网络流量类型（包括正常流量和14种攻击类型）
- 💻 **图形界面** | **GUI Interface**: 基于PyQt5的友好用户界面
- 📈 **可视化展示** | **Visualization**: 实时显示检测结果和流量统计信息

## 🔧 技术栈 | Technology Stack

### 核心框架 | Core Frameworks
- **深度学习** | **Deep Learning**: PyTorch
- **数据处理** | **Data Processing**: Pandas, NumPy
- **机器学习** | **Machine Learning**: Scikit-learn
- **网络抓包** | **Network Capture**: Scapy
- **图形界面** | **GUI**: PyQt5

### 工具 | Tools
- **特征生成** | **Feature Generation**: CICFlowMeter 4.0
- **数据格式** | **Data Format**: PCAP, CSV

## 📁 项目结构 | Project Structure

```
bishe/
├── data_preprocess/          # 数据预处理模块 | Data preprocessing module
│   ├── get_feature.py       # 特征提取 | Feature extraction
│   └── process_feature.py   # 特征处理 | Feature processing
├── train_model/             # 训练好的模型 | Trained models
│   ├── CNN.pth             # CNN模型 | CNN model
│   ├── AlexNet8.pth        # AlexNet模型 | AlexNet model
│   └── VGG16.pth           # VGG16模型 | VGG16 model
├── cicflowmeter-4/          # CICFlowMeter工具 | CICFlowMeter tool
├── netdata/                 # 网络数据目录 | Network data directory
│   ├── captured_traffic.pcap           # 捕获的原始数据包 | Captured raw packets
│   ├── captured_traffic.pcap_Flow.csv  # 提取的流量特征 | Extracted flow features
│   └── fin_data.csv                    # 处理后的数据 | Processed data
├── model.py                 # 模型定义 | Model definitions
├── train_1.py              # 模型训练 | Model training
├── predict.py              # 预测模块 | Prediction module
├── ui.py                   # 图形界面 | GUI interface
├── variable.py             # 全局变量 | Global variables
└── sniff.py                # 抓包模块 | Packet sniffing module
```

## 🚀 安装与配置 | Installation & Configuration

### 前置要求 | Prerequisites

1. **Python环境** | **Python Environment**: Python 3.7+
2. **libpcap/WinPcap**: 
   - Windows: [WinPcap](https://www.winpcap.org/install/default.htm)
   - Linux: `sudo apt-get install libpcap-dev`

### 安装依赖 | Install Dependencies

```bash
pip install torch numpy pandas scikit-learn scapy pyqt5
```

### 配置说明 | Configuration

1. 确保已安装WinPcap（Windows）或libpcap（Linux）
2. 修改 `ui.py` 中的网络接口名称（默认"WLAN"）
3. 根据需要调整模型路径和数据目录

## 📖 使用方法 | Usage

### 1. 使用图形界面 | Using GUI

```bash
python ui.py
```

操作步骤 | Steps:
1. 输入要捕获的数据包数量 | Enter the number of packets to capture
2. 点击"开始捕获"按钮 | Click "Start Capture" button
3. 等待捕获完成后，点击"开始检测"按钮 | After capture completes, click "Start Detection" button
4. 查看检测结果表格 | View the detection results table

### 2. 训练模型 | Train Models

```bash
python train_1.py
```

该脚本会：
- 加载数据集 | Load dataset
- 数据预处理（标准化、归一化） | Data preprocessing (standardization, normalization)
- 训练CNN、AlexNet、VGG16三个模型 | Train three models: CNN, AlexNet, VGG16
- 自动保存最佳模型到 `train_model/` 目录 | Automatically save best models to `train_model/` directory

### 3. 单独进行预测 | Predict Only

```python
from predict import pre
pre()
```

## 🎯 支持的流量类型 | Supported Traffic Types

系统可以识别以下15种流量类型 | The system can recognize the following 15 traffic types:

1. **BENIGN** - 正常流量 | Normal traffic
2. **Bot** - 僵尸网络 | Botnet
3. **DDoS** - 分布式拒绝服务攻击 | Distributed Denial of Service
4. **DoS GoldenEye** - GoldenEye拒绝服务攻击
5. **DoS Hulk** - Hulk拒绝服务攻击
6. **DoS Slowhttptest** - SlowHTTP测试攻击
7. **DoS slowloris** - Slowloris攻击
8. **FTP-Patator** - FTP暴力破解
9. **Heartbleed** - 心脏滴血漏洞攻击
10. **Infiltration** - 渗透攻击
11. **PortScan** - 端口扫描
12. **SSH-Patator** - SSH暴力破解
13. **Web Attack - Brute Force** - Web暴力破解攻击
14. **Web Attack - Sql Injection** - SQL注入攻击
15. **Web Attack - XSS** - 跨站脚本攻击

## 📊 模型架构 | Model Architecture

### CNN模型 | CNN Model
- 4层卷积层 | 4 Convolutional layers
- Batch Normalization
- ReLU激活函数 | ReLU activation
- 平均池化 | Average pooling
- Dropout正则化 | Dropout regularization

### AlexNet8模型 | AlexNet8 Model
- 5层卷积层 | 5 Convolutional layers
- 3层全连接层 | 3 Fully connected layers
- Max Pooling
- Dropout (0.5)

### VGG16模型 | VGG16 Model
- 13层卷积层 | 13 Convolutional layers
- 3层全连接层 | 3 Fully connected layers
- Batch Normalization
- Dropout (0.2-0.5)

## 📝 数据流程 | Data Flow

```
网络数据包捕获 → CICFlowMeter特征提取 → 数据预处理 → 模型预测 → 结果展示
     ↓                    ↓                    ↓            ↓           ↓
  PCAP文件          CSV特征文件          标准化/归一化    分类结果     GUI表格
```

```
Packet Capture → Feature Extraction → Data Preprocessing → Model Prediction → Results Display
     ↓                    ↓                    ↓            ↓           ↓
  PCAP file          CSV feature file    Standardization   Classification  GUI Table
                                    /Normalization      Results
```

## ⚙️ 配置文件说明 | Configuration Files

### variable.py
包含全局变量和配置 | Contains global variables and configurations:
- `columns`: 特征列名列表 | Feature column names list
- `device`: 计算设备选择（CPU/GPU） | Computing device selection (CPU/GPU)
- `LoadData`: 数据加载器类 | Data loader class

### 特征列表 | Feature List
系统使用78个网络流量特征，包括：
- 流持续时间、包数量、字节数
- 包长度统计（最大值、最小值、均值、标准差）
- 流间隔时间统计
- TCP标志位计数
- 活跃/空闲时间统计

The system uses 78 network traffic features, including:
- Flow duration, packet count, byte count
- Packet length statistics (max, min, mean, std)
- Flow inter-arrival time statistics
- TCP flag counts
- Active/Idle time statistics

## 🔬 开发说明 | Development Notes

### 添加新模型 | Adding New Models

1. 在 `model.py` 中定义模型类 | Define model class in `model.py`
2. 继承 `nn.Module` 并实现 `forward` 方法 | Inherit `nn.Module` and implement `forward` method
3. 在 `train_1.py` 中添加训练逻辑 | Add training logic in `train_1.py`
4. 在 `predict.py` 中集成预测功能 | Integrate prediction in `predict.py`

### 自定义特征 | Customizing Features

修改以下文件中的特征列配置 | Modify feature column configuration in:
- `data_preprocess/process_feature.py`
- `variable.py`
- `predict.py`

## 📚 数据集 | Dataset

本项目使用公开的网络入侵检测数据集进行训练，建议使用：
- CICIDS2017
- NSL-KDD
- 或其他包含多种攻击类型的网络流量数据集

This project uses public network intrusion detection datasets for training. Recommended:
- CICIDS2017
- NSL-KDD
- Or other network traffic datasets with multiple attack types

## 📄 引用 | Citation

如果本项目对您的研究有帮助，请引用：

If this project helps your research, please cite:

```bibtex
Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun and Ali A. Ghorbani, 
"Characterization of Tor Traffic Using Time Based Features", 
In the proceeding of the 3rd International Conference on Information System Security and Privacy, 
SCITEPRESS, Porto, Portugal, 2017

Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, Ali A. Ghorbani, 
"Characterization of Encrypted and VPN Traffic Using Time-Related Features", 
In Proceedings of the 2nd International Conference on Information Systems Security and Privacy(ICISSP 2016), 
pages 407-414, Rome, Italy
```

## ⚠️ 注意事项 | Notes

1. **权限要求** | **Permission Requirements**: 抓包需要管理员/root权限
2. **网络接口** | **Network Interface**: 确保选择正确的网络接口名称
3. **性能优化** | **Performance Optimization**: 建议使用GPU加速训练
4. **数据质量** | **Data Quality**: 训练数据质量直接影响检测准确率

---

**注意** | **Note**: 本系统仅用于学术研究和教育目的。在生产环境中使用前，请进行充分的测试和评估。

**Disclaimer**: This system is for academic research and educational purposes only. Please conduct thorough testing and evaluation before using in production environments.
