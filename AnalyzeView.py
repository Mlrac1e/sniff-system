import sys
import pandas as pd
import pyshark
import matplotlib.pyplot as plt
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QComboBox, QPushButton, QFileDialog, QWidget, QMessageBox, QListWidget, QListWidgetItem, QScrollArea
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QImage, QColor, QFont

class AnalyzeView(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("流量分析")
        self.setFixedSize(1280, 960)

        # 创建选择文件按钮
        self.open_file_button = QPushButton("选择文件")
        self.open_file_button.clicked.connect(self.open_file_dialog)

        # 创建选择分析字段的下拉框
        self.field_combo = QListWidget()

        # 创建分析按钮
        self.analyze_button = QPushButton("开始分析")
        self.analyze_button.setEnabled(False)
        self.analyze_button.clicked.connect(self.analyze_data)

        # 创建数据可视化展示区域
        self.visualization_widget = QWidget()
        self.visualization_layout = QVBoxLayout(self.visualization_widget)
        self.visualization_scroll_area = QScrollArea()
        self.visualization_scroll_area.setWidgetResizable(True)
        self.visualization_scroll_area.setWidget(self.visualization_widget)

        # 创建布局并添加控件
        layout = QVBoxLayout()
        layout.addWidget(self.open_file_button)
        layout.addWidget(QLabel("选择分析字段"))
        layout.addWidget(self.field_combo)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.visualization_scroll_area)

        # 设置布局到主窗口
        self.widget = QWidget()
        self.widget.setLayout(layout)
        self.setCentralWidget(self.widget)

        self.data = pd.DataFrame()  # 保存的数据文件

    def open_file_dialog(self):
        # 打开文件对话框选择pcap文件
        file_path, _ = QFileDialog.getOpenFileName(self, "选择数据文件", "./", "PCAP Files (*.pcap)")
        if file_path:
            # 通过PyShark读取pcap文件数据
            cap = pyshark.FileCapture(file_path)
            for packet in cap:
                # 提取感兴趣的字段，例如源IP和目的IP
                packet_data = {
                    "Source IP": packet.ip.src,
                    "Destination IP": packet.ip.dst
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

        # 对每个选择的字段进行分析
        for field in selected_fields:
            analysis_result = self.data[field].value_counts()

            # 数据可视化
            plt.figure(figsize=(8, 6))
            analysis_result.plot(kind='bar')
            plt.xlabel(field)
            plt.ylabel("Count")
            plt.title(f"Analysis of {field}")
            plt.tight_layout()

            # 将Matplotlib图形转换为Qt图像
            fig = plt.gcf()
            fig.canvas.draw()
            image = fig.canvas.tostring_rgb()
            plt.close()

            # 将Qt图像显示在界面上
            pixmap = QPixmap.fromImage(QImage(image, fig.canvas.get_width_height()[0], fig.canvas.get_width_height()[1], QImage.Format_RGB888))
            label = QLabel(self.visualization_widget)
            label.setPixmap(pixmap)

            # 设置标签样式
            label.setStyleSheet("QLabel { background-color: white; border: 1px solid #c4c4c4; padding: 10px; }")
            label.setAlignment(Qt.AlignCenter)

            # 调整标签的大小策略
            label.setScaledContents(True)

            # 调整字体样式
            font = QFont()
            font.setBold(True)
            label.setFont(font)

            # 添加标签到布局
            self.visualization_layout.addWidget(label)
