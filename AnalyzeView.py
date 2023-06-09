
import pandas as pd
import altair as alt
import numpy as np
import tensorflow as tf

import pyshark
from sklearn.preprocessing import MinMaxScaler
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton, QFileDialog, QWidget, QMessageBox, QListWidget, QScrollArea, QTextEdit, QLineEdit
from PySide6.QtCore import Qt
from PySide6.QtWebEngineWidgets import QWebEngineView


def extract_features_from_pcap(file_path, source_ip):
    # 使用pyshark读取PCAP文件
    cap = pyshark.FileCapture(file_path)

    # 初始化各种变量以存储特征
    total_fwd_bytes = 0
    total_bwd_bytes = 0
    fwd_packets = 0
    bwd_packets = 0
    bwd_packet_lengths = []
    fwd_packet_lengths = []
    psh_flags = 0
    timestamps = []
    init_win_bytes_forward = None

    # 遍历PCAP文件中的每个数据包
    for packet in cap:
        # 检查数据包是否包含IP层
        if hasattr(packet, 'ip'):
            # 检查数据包是否包含TCP层
            if hasattr(packet, 'tcp'):
                # 判断此数据包是“向前”还是“向后”（根据源IP）
                if packet.ip.src == source_ip:
                    total_fwd_bytes += int(packet.tcp.len) # 计算向前的总字节数
                    fwd_packets += 1  # 计算向前的数据包数量
                    fwd_packet_lengths.append(int(packet.tcp.len))  # 存储每个向前的数据包长度
                    # 存储向前的初始窗口大小（仅对第一个数据包）
                    if init_win_bytes_forward is None:
                        init_win_bytes_forward = int(packet.tcp.window_size_value)
                else:
                    total_bwd_bytes += int(packet.tcp.len) # 计算向后的总字节数
                    bwd_packets += 1  # 计算向后的数据包数量
                    bwd_packet_lengths.append(int(packet.tcp.len))  # 存储每个向后的数据包长度
                
                # 检查TCP数据包是否设置了PSH标志
                if hasattr(packet.tcp, 'flags_psh') and packet.tcp.flags_psh == '1':
                    psh_flags += 1  # 计算设置了PSH标志的数据包数量

                # 存储数据包的时间戳
                timestamps.append(float(packet.sniff_timestamp))

    # 计算流持续时间（最后一个和第一个数据包的时间差）
    flow_duration = max(timestamps) - min(timestamps) if timestamps else 0
    # 计算流的到达时间的标准差
    flow_iat_std = np.std(np.diff(timestamps)) if timestamps else 0
    # 向后的数据包的最小长度
    bwd_packet_length_min = min(bwd_packet_lengths) if bwd_packet_lengths else 0
    # 向后的数据包长度的标准差
    bwd_packet_length_std = np.std(bwd_packet_lengths) if bwd_packet_lengths else 0
    # 向前的数据包长度的平均值
    fwd_packet_length_mean = np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0
    # 每秒向后的数据包数量
    bwd_packets_per_second = bwd_packets / flow_duration if flow_duration > 0 else 0
    # 平均数据包大小
    avg_packet_size = (total_fwd_bytes + total_bwd_bytes) / (fwd_packets + bwd_packets) if fwd_packets + bwd_packets > 0 else 0

    # 返回提取的特征作为列表
    return [
        bwd_packet_length_min,
        total_fwd_bytes,
        total_fwd_bytes,
        fwd_packet_length_mean,
        bwd_packet_length_std,
        flow_duration,
        flow_iat_std,
        init_win_bytes_forward,
        bwd_packets_per_second,
        psh_flags,
        avg_packet_size
    ]

    

class AnalyzeView(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("流量分析")
        self.setFixedSize(1280, 960)
        self.file_path = ""
        self.source_ip = ""  # 存储源IP地址

        # 创建选择文件按钮
        self.open_file_button = QPushButton("选择文件")
        self.open_file_button.clicked.connect(self.open_file_dialog)

        # 创建选择分析字段的下拉框
        self.field_combo = QListWidget()
        self.field_combo.setMaximumHeight(150)  # 限制下拉框的高度

        # 创建分析按钮
        self.analyze_button = QPushButton("开始分析")
        self.analyze_button.setEnabled(False)
        self.analyze_button.clicked.connect(self.analyze_data)

        # 创建数据可视化展示区域
        self.visualization_widget = QWidget()
        self.visualization_layout = QVBoxLayout(self.visualization_widget)
        self.visualization_layout.setSpacing(10)  # 设置图表之间的间距
        self.visualization_scroll_area = QScrollArea()
        self.visualization_scroll_area.setWidgetResizable(True)
        self.visualization_scroll_area.setWidget(self.visualization_widget)
        self.visualization_scroll_area.setMinimumHeight(600)  # 设置最小高度

        # 创建攻击检测按钮
        self.attack_detection_button = QPushButton("攻击检测")
        self.attack_detection_button.setEnabled(True)
        self.attack_detection_button.clicked.connect(self.perform_attack_detection)

        # 创建文本框用于显示检测结果
        self.result_text_edit = QTextEdit()
        self.result_text_edit.setReadOnly(True)

        # 创建源IP输入框
        self.source_ip_input = QLineEdit()
        self.source_ip_input.setPlaceholderText("输入源IP地址")

        # 创建布局并添加控件
        layout = QVBoxLayout()
        layout.addWidget(self.open_file_button)
        layout.addWidget(QLabel("选择分析字段"))
        layout.addWidget(self.field_combo)
        layout.addWidget(self.analyze_button)
        layout.addWidget(QLabel("源IP地址"))
        layout.addWidget(self.source_ip_input)  # 添加源IP输入框
        layout.addWidget(self.attack_detection_button)
        layout.addWidget(self.visualization_scroll_area)
        layout.addWidget(self.result_text_edit)

        # 设置布局到主窗口
        self.widget = QWidget()
        self.widget.setLayout(layout)
        self.setCentralWidget(self.widget)

        self.data = pd.DataFrame()  # 保存的数据文件

    def open_file_dialog(self):
        # 打开文件对话框选择pcap文件
        file_path, _ = QFileDialog.getOpenFileName(self, "选择数据文件", "./", "PCAP Files (*.pcap)")
        self.file_path = file_path
        if file_path:
            # 通过PyShark读取pcap文件数据
            cap = pyshark.FileCapture(file_path)
            for packet in cap:
               if hasattr(packet, 'ip'): 
                if hasattr(packet, 'tcp'):
                    srcport = packet.tcp.srcport
                    dstport = packet.tcp.dstport
                elif hasattr(packet, 'udp'):
                    srcport = packet.udp.srcport
                    dstport = packet.udp.dstport
                else:
                    srcport = None
                    dstport = None
                
                # 提取感兴趣的字段，例如源IP，目的IP，协议类型，数据包长度等
                packet_data = {
                    "Source IP": packet.ip.src,
                    "Destination IP": packet.ip.dst,
                    "Protocol": packet.transport_layer,
                    "Length": packet.length,
                    "Source Port": srcport,
                    "Destination Port": dstport
                }
                self.data = pd.concat([self.data, pd.DataFrame(packet_data, index=[0])], ignore_index=True)

            # 更新选择分析字段的下拉框
            self.field_combo.clear()
            self.field_combo.addItems(self.data.columns)
            self.analyze_button.setEnabled(True)

    def analyze_data(self):
        # 获取选择的分析字段
        selected_fields = [item.text() for item in self.field_combo.selectedItems()]

        # 检查选择的字段是否为空
        if not selected_fields:
            # 如果为空，提示用户选择有效的字段
            QMessageBox.warning(self, "错误", "请选择有效的分析字段")
            return
        
        # 清除可视化布局中之前的图表
        for i in reversed(range(self.visualization_layout.count())):
            self.visualization_layout.itemAt(i).widget().setParent(None)
        
        # 对每个选择的字段进行分析
        for field in selected_fields:
            # 使用Altair创建条形图
            chart = alt.Chart(self.data).mark_bar().encode(
                y=alt.X(f'{field}:N', title=field),
                x=alt.Y('count()', title='Count')
            ).properties(
                width=800,
                height=600,
                title=f'{field}的分析结果'
            ).configure_axis(
            labelFontSize=14  # 设置轴标签字体大小
        )

            # 使用QWebEngineView显示HTML内容
            web_view = QWebEngineView(self.visualization_widget)
            web_view.setHtml(chart.to_html())
            self.visualization_layout.addWidget(web_view)

    def perform_attack_detection(self):
        if not self.file_path:
            QMessageBox.warning(self, "错误", "请选择数据文件")
            return

        self.source_ip = self.source_ip_input.text()  # 从输入框中获取源IP地址
        

        features_array = extract_features_from_pcap(self.file_path, self.source_ip)
        features_array = np.array(features_array).reshape(1, -1)
    
        # 使用MinMaxScaler进行归一化
        scaler = MinMaxScaler()
        normalized_features = scaler.fit_transform(features_array)

          # 返回归一化的特征作为列表
        normalized_features = normalized_features[0].tolist()
  
    
        
        feature_names = ['Bwd_Packet_Length_Min','Subflow_Fwd_Bytes','Total_Length_of_Fwd_Packets','Fwd_Packet_Length_Mean','Bwd_Packet_Length_Std','Flow_Duration','Flow_IAT_Std','Init_Win_bytes_forward','Bwd_Packets/s',
                 'PSH_Flag_Count','Average_Packet_Size']
        # 将特征转换为字典
        features_dict = {name: np.array([value]) for name, value in zip(feature_names, normalized_features)}

        # 加载保存的模型
        reconstructed_model = tf.keras.models.load_model('Final_Model')

        # 进行推断
        inference_ds = tf.data.Dataset.from_tensor_slices(features_dict).batch(1)
        predictions = reconstructed_model.predict(inference_ds)

        # 输出预测结果
        class_names = ['Class1', 'Class2', 'Class3', 'Class4']
        result = ""
        for prediction in predictions:
            predicted_class = class_names[prediction.argmax()]
            if predicted_class == 'Class1':
                result += '未受到攻击\n'
            else:
                result += '受到攻击\n'

        # 显示检测结果
        self.result_text_edit.setText(result)
