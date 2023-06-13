import threading
import pyshark
import shutil
from pyshark.tshark import tshark
from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QComboBox, QFileDialog, QMessageBox
from PySide6.QtCore import Qt, QTimer
from datetime import datetime
from PySide6.QtGui import QColor


class CaptureView(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("数据捕获")
        self.setFixedSize(1280, 960)
        self.file_path = None

        # 创建网卡选择下拉框
        self.interface_combo = QComboBox()

        # 获取可用网卡列表
        available_interfaces = tshark.get_all_tshark_interfaces_names()
        for interface in available_interfaces:
            self.interface_combo.addItem(interface)

        # 创建捕获数据显示表格
        self.table = QTableWidget()
        self.table.setColumnCount(6)  # 设置列数为6
        self.table.setHorizontalHeaderLabels(["捕获时间", "源地址", "目的地址", "协议类型", "数据大小", "数据内容"])
        self.table.itemClicked.connect(self.show_packet_data)

        # 创建数据内容详细显示文本框
        self.data_text = QTextEdit()
        self.data_text.setReadOnly(True)

        # 创建过滤器输入框和按钮
        self.filter_input = QLineEdit()
        self.filter_button = QPushButton("过滤")
        self.filter_button.clicked.connect(self.filter_data)

        # 创建开始和停止捕获按钮
        self.start_button = QPushButton("开始捕获")
        self.start_button.clicked.connect(self.start_capture_thread)
        self.stop_button = QPushButton("停止捕获")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture_thread)

        # 创建保存数据按钮
        self.save_button = QPushButton("保存数据")
        self.save_button.clicked.connect(self.save_data)

        # 创建布局并添加控件
        layout = QVBoxLayout()
        filter_layout = QHBoxLayout()
        capture_layout = QHBoxLayout()
        layout.addWidget(QLabel("网卡选择"))
        layout.addWidget(self.interface_combo)
        layout.addWidget(QLabel("捕获数据"))
        layout.addWidget(self.table)
        layout.addWidget(QLabel("数据内容"))
        layout.addWidget(self.data_text)
        filter_layout.addWidget(QLabel("过滤器"))
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.filter_button)
        layout.addLayout(filter_layout)
        capture_layout.addWidget(self.start_button)
        capture_layout.addWidget(self.stop_button)
        layout.addLayout(capture_layout)
        layout.addWidget(self.save_button)

        # 创建主部件并设置布局
        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        self.capture_thread = None  # 捕包线程
        self.capture = None  # PyShark抓包实例
        self.captured_packets = []  # 捕获的数据包列表

        # 添加定时器，每秒检查异常流量
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_abnormal_traffic)

    def filter_data(self):
        # 根据过滤器条件筛选数据并更新表格显示
        filter_text = self.filter_input.text()
        filtered_packets = self.filter_packets(filter_text)
        self.update_table_data(filtered_packets)

    def start_capture_thread(self):
        # 启动捕包线程
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        # 获取选择的网卡
        selected_interface = self.interface_combo.currentText()

        # 创建并启动捕包线程
        self.capture_thread = threading.Thread(target=self.capture_packets, args=(selected_interface,))
        self.capture_thread.start()

        # 启动定时器
        self.timer.start(1000)

    def stop_capture_thread(self):
        # 停止捕包线程
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        # 停止捕包线程
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join()

        # 停止定时器
        self.timer.stop()

    def capture_packets(self, interface):
        # 捕获数据包的线程函数
        self.capture = pyshark.LiveCapture(interface=interface,output_file="test.pcap")
        self.capture.sniff(timeout=10)
        self.capture.close()  # 确保捕获会话已关闭
        self.captured_packets = self.capture._packets
        self.update_table_data(self.captured_packets)


    def update_table_data(self, packets):
        self.table.setRowCount(len(packets))

        for row, packet in enumerate(packets):
            capture_time = QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            source_address_item = QTableWidgetItem(packet.layers[1].src)
            destination_address_item = QTableWidgetItem(packet.ip.dst)
            protocol_item = QTableWidgetItem(self.get_protocol_type(packet))
            total_length_item = QTableWidgetItem(str(packet.length))
            data_content_item = QTableWidgetItem("点击查看")
            data_content_item.setData(Qt.UserRole, str(packet))

            self.table.setItem(row, 0, capture_time)
            self.table.setItem(row, 1, source_address_item)
            self.table.setItem(row, 2, destination_address_item)
            self.table.setItem(row, 3, protocol_item)
            self.table.setItem(row, 4, total_length_item)
            self.table.setItem(row, 5, data_content_item)
            # 根据协议类型设置行背景颜色
            if protocol_item.text() == "TCP":
                protocol_item.setBackground(QColor(255, 255, 0))
            elif protocol_item.text() == "UDP":
                protocol_item.setBackground(QColor(0, 255, 0))
            else:
                protocol_item.setBackground(QColor(255, 0, 0))

        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()

    def get_protocol_type(self, packet):
        if hasattr(packet, 'transport_layer'):
            if packet.transport_layer == 'TCP':
                return 'TCP'
            elif packet.transport_layer == 'UDP':
                return 'UDP'
        return 'Unknown'

    def show_packet_data(self, item):
        # 显示数据包的详细内容
        packet_data = item.data(Qt.UserRole)
        self.data_text.clear()
        self.data_text.insertPlainText(packet_data)



    def save_data(self):
        # 获取保存文件的路径
        file_path, _ = QFileDialog.getSaveFileName(self, "保存数据", "./", "PCAP Files (*.pcap)")

        if file_path:
        # 将test.pcap文件复制到指定路径
            shutil.copyfile("test.pcap", file_path)
        

        QMessageBox.information(self, "成功", "数据保存成功！")



    def filter_packets(self, filter_text):
        filtered_packets = []

        for packet in self.captured_packets:
            if filter_text in str(packet):
                filtered_packets.append(packet)

        return filtered_packets


    def check_abnormal_traffic(self):
        # 检测异常流量
        total_packets = len(self.captured_packets)

        if total_packets > 1000:
            # 处理大规模数据流量
            self.process_large_traffic(total_packets)

        if total_packets > 0:
            # 对每个数据包进行攻击检测
            self.detect_attacks()
