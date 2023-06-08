import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton
from PySide6.QtCore import Qt
from CaptureView import CaptureView
from AnalyzeView import AnalyzeView



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Main Window")
        self.setFixedSize(1280, 960)  # 设置窗口大小为1280x960c

        self.setStyleSheet("""
            QMainWindow {
                background: #f5f5f5;
            }

            QLabel {
                font-size: 24px;
                color: #333333;
                padding: 20px;
                background-color: #ffffff;
                border-radius: 25px;
            }

            QPushButton {
                font-size: 18px;
                color: #ffffff;
                background-color: #007bff;
                padding: 10px 20px;
                border-radius: 25px;
            }

            QPushButton:hover {
                background-color: #0056b3;
            }
        """)

        self.title_label = QLabel("流量分析与安全检测系统设计", self)
        self.title_label.setGeometry(400, 200, 480, 100)  # 设置标题的位置和大小
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.button1 = QPushButton("数据捕获", self)
        self.button1.setGeometry(400, 400, 200, 50)  # 设置按钮1的位置和大小
        self.button1.clicked.connect(self.open_capture_view)  # 连接按钮的点击事件到槽函数

        self.button2 = QPushButton("流量分析", self)
        self.button2.setGeometry(680, 400, 200, 50)  # 设置按钮2的位置和大小
        self.button2.clicked.connect(self.open_analyze_view)  # 连接按钮的点击事件到槽函数
        
    def open_capture_view(self):
        capture_view = CaptureView()
       
        capture_view.show()
        capture_view.exec()
    
    def open_analyze_view(self):
        analyze_view = AnalyzeView()
        analyze_view.show()
        analyze_view.exec()




if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()
