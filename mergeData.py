


# 根据file读取数据
import pandas as pd


def writeData(file):
    print("Loading raw data...")
    raw_data = pd.read_csv(file, header=None, low_memory=False)
    # 剔除第一行属性特征名称
    return raw_data.drop([0])


# 按行合并多个Dataframe数据
def mergeData():
    monday = writeData("./data/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv")

    friday1 = writeData("./data/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

    friday2 = writeData("./data/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

    friday3 = writeData("./data/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv")

    thursday1 = writeData("./data/MachineLearningCVE/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv")

    thursday2 = writeData("./data/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")

    tuesday = writeData("./data/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv")

    wednesday = writeData("./data/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv")

    frame = [monday, friday1, friday2, friday3, thursday1, thursday2, tuesday, wednesday]

    # 合并数据
    result = pd.concat(frame)
    list = clearDirtyData(result)
    result = result.drop(list)
    return result


# 清除CIC-IDS数据集中的脏数据，第一行特征名称和含有Nan、Infiniti等数据的行数
def clearDirtyData(df):
    dropList = df[(df[14] == "Nan") | (df[15] == "Infinity")].index.tolist()
    return dropList


def analyseData(data):
    # 得到标签列索引
    last_column_index = data.shape[1] - 1
    print("-----data lable-----\n{}".format(data.iloc[:,last_column_index].value_counts()))


def savetotal():
    Dedata = mergeData()
    file = './data/total.csv'
    Dedata.to_csv(file, index=False, header=False)


if __name__ == '__main__':
    #savetotal()
    data = pd.read_csv('data/total.csv')
    analyseData(data)
