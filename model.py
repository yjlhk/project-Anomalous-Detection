from torch import nn


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


class AlexNet8(nn.Module):
    def __init__(self):
        super(AlexNet8, self).__init__()
        self.c1 = nn.Conv2d(in_channels=1, out_channels=96, kernel_size=3, padding=1)
        self.b1 = nn.BatchNorm2d(96)
        self.a1 = nn.ReLU()
        self.p1 = nn.MaxPool2d(kernel_size=3, stride=1, padding=1)

        self.c2 = nn.Conv2d(in_channels=96, out_channels=256, kernel_size=3, padding=1)
        self.b2 = nn.BatchNorm2d(256)
        self.a2 = nn.ReLU()
        self.p2 = nn.MaxPool2d(kernel_size=3, stride=2, padding=1)

        self.c3 = nn.Conv2d(in_channels=256, out_channels=384, kernel_size=3, padding=1)
        self.a3 = nn.ReLU()

        self.c4 = nn.Conv2d(in_channels=384, out_channels=384, kernel_size=3, padding=1)
        self.a4 = nn.ReLU()

        self.c5 = nn.Conv2d(in_channels=384, out_channels=256, kernel_size=3, padding=1)
        self.p3 = nn.MaxPool2d(kernel_size=3, stride=2, padding=1)

        self.flatten = nn.Flatten()
        self.f1 = nn.Linear(2048, 2048)  # 修改全连接层的输入大小
        self.a5 = nn.ReLU()
        self.d1 = nn.Dropout(0.5)
        self.f2 = nn.Linear(2048, 2048)
        self.a6 = nn.ReLU()
        self.d2 = nn.Dropout(0.5)
        self.f3 = nn.Linear(2048, 15)  # 修改最终预测的类别数

    def forward(self, x):
        x = self.c1(x)
        x = self.b1(x)
        x = self.a1(x)
        x = self.p1(x)

        x = self.c2(x)
        x = self.b2(x)
        x = self.a2(x)
        x = self.p2(x)

        x = self.c3(x)
        x = self.a3(x)

        x = self.c4(x)
        x = self.a4(x)

        x = self.c5(x)
        x = self.p3(x)

        x = self.flatten(x)
        x = self.f1(x)
        x = self.a5(x)
        x = self.d1(x)
        x = self.f2(x)
        x = self.a6(x)
        x = self.d2(x)
        x = self.f3(x)
        return x



class VGG16(nn.Module):
    def __init__(self):
        super(VGG16, self).__init__()
        self.c1 = nn.Conv2d(in_channels=1, out_channels=64, kernel_size=3, padding=1)  # 卷积层1
        self.b1 = nn.BatchNorm2d(64)  # BN层1
        self.a1 = nn.ReLU()  # 激活层1
        self.c2 = nn.Conv2d(in_channels=64, out_channels=64, kernel_size=3, padding=1)
        self.b2 = nn.BatchNorm2d(64)  # BN层1
        self.a2 = nn.ReLU()  # 激活层1
        self.p1 = nn.MaxPool2d(kernel_size=2, stride=1)  # 最大池化层1
        self.d1 = nn.Dropout(0.2)  # dropout层

        self.c3 = nn.Conv2d(in_channels=64, out_channels=128, kernel_size=3, padding=1)
        self.b3 = nn.BatchNorm2d(128)  # BN层1
        self.a3 = nn.ReLU()  # 激活层1
        self.c4 = nn.Conv2d(in_channels=128, out_channels=128, kernel_size=3, padding=1)
        self.b4 = nn.BatchNorm2d(128)  # BN层1
        self.a4 = nn.ReLU()  # 激活层1
        self.p2 = nn.MaxPool2d(kernel_size=2, stride=1)  # 最大池化层2
        self.d2 = nn.Dropout(0.2)  # dropout层

        self.c5 = nn.Conv2d(in_channels=128, out_channels=256, kernel_size=3, padding=1)
        self.b5 = nn.BatchNorm2d(256)  # BN层1
        self.a5 = nn.ReLU()    # 激活层1
        self.c6 = nn.Conv2d(in_channels=256, out_channels=256, kernel_size=3, padding=1)
        self.b6 = nn.BatchNorm2d(256)  # BN层1
        self.a6 = nn.ReLU()    # 激活层1
        self.c7 = nn.Conv2d(in_channels=256, out_channels=256, kernel_size=3, padding=1)
        self.b7 = nn.BatchNorm2d(256)
        self.a7 = nn.ReLU()
        self.p3 = nn.MaxPool2d(kernel_size=2, stride=1)  # 最大池化层3
        self.d3 = nn.Dropout(0.2)

        self.c8 = nn.Conv2d(in_channels=256, out_channels=512, kernel_size=3, padding=1)
        self.b8 = nn.BatchNorm2d(512)  # BN层1
        self.a8 = nn.ReLU()    # 激活层1
        self.c9 = nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, padding=1)
        self.b9 = nn.BatchNorm2d(512)  # BN层1
        self.a9 = nn.ReLU()    # 激活层1
        self.c10 = nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, padding=1)
        self.b10 = nn.BatchNorm2d(512)
        self.a10 = nn.ReLU()
        self.p4 = nn.MaxPool2d(kernel_size=2, stride=1)  # 最大池化层4
        self.d4 = nn.Dropout(0.2)

        self.c11 = nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, padding=1)
        self.b11 = nn.BatchNorm2d(512)  # BN层1
        self.a11 = nn.ReLU()    # 激活层1
        self.c12 = nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, padding=1)
        self.b12 = nn.BatchNorm2d(512)  # BN层1
        self.a12 = nn.ReLU()    # 激活层1
        self.c13 = nn.Conv2d(in_channels=512, out_channels=512, kernel_size=3, padding=1)
        self.b13 = nn.BatchNorm2d(512)
        self.a13 = nn.ReLU()
        self.p5 = nn.MaxPool2d(kernel_size=2, stride=1)  # 最大池化层5
        self.d5 = nn.Dropout(0.2)

        self.flatten = nn.Flatten()
        self.f1 = nn.Linear(4096, 4096)  # 全连接层1
        self.a14 = nn.ReLU()  # 激活层1
        self.d6 = nn.Dropout(0.5)
        self.f2 = nn.Linear(4096, 4096)  # 全连接层2
        self.a15 = nn.ReLU()  # 激活层2
        self.d7 = nn.Dropout(0.5)
        self.f3 = nn.Linear(4096, 15)  # 全连接层3（输出层）

    def forward(self, x):
        x = self.c1(x)
        x = self.b1(x)
        x = self.a1(x)
        x = self.c2(x)
        x = self.b2(x)
        x = self.a2(x)
        x = self.p1(x)
        x = self.d1(x)

        x = self.c3(x)
        x = self.b3(x)
        x = self.a3(x)
        x = self.c4(x)
        x = self.b4(x)
        x = self.a4(x)
        x = self.p2(x)
        x = self.d2(x)

        x = self.c5(x)
        x = self.b5(x)
        x = self.a5(x)
        x = self.c6(x)
        x = self.b6(x)
        x = self.a6(x)
        x = self.c7(x)
        x = self.b7(x)
        x = self.a7(x)
        x = self.p3(x)
        x = self.d3(x)

        x = self.c8(x)
        x = self.b8(x)
        x = self.a8(x)
        x = self.c9(x)
        x = self.b9(x)
        x = self.a9(x)
        x = self.c10(x)
        x = self.b10(x)
        x = self.a10(x)
        x = self.p4(x)
        x = self.d4(x)

        x = self.c11(x)
        x = self.b11(x)
        x = self.a11(x)
        x = self.c12(x)
        x = self.b12(x)
        x = self.a12(x)
        x = self.c13(x)
        x = self.b13(x)
        x = self.a13(x)
        x = self.p5(x)
        x = self.d5(x)

        x = self.flatten(x)
        x = self.f1(x)
        x = self.a14(x)
        x = self.d6(x)
        x = self.f2(x)
        x = self.a15(x)
        x = self.d7(x)
        y = self.f3(x)
        return y
