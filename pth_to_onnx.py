
import torch.onnx

# 定义你的CNN模型（确保这个定义和你训练模型时的定义相同）

# 加载模型
from model import CNN

model = CNN()
model_path = './train_model/CNN.pth'
model.load_state_dict(torch.load(model_path))

# 设置模型为评估模式
model.eval()

# 创建一个示例输入（假设输入形状为 (1, 1, 6, 13)）
dummy_input = torch.randn(1, 1, 6, 13)

# 导出模型
onnx_path = './train_model/CNN.onnx'
torch.onnx.export(model, dummy_input, onnx_path,
                  input_names=['input'], output_names=['output'],
                  dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}})

print(f"Model has been converted to ONNX and saved at {onnx_path}")
