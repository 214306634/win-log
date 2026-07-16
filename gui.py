# -*- coding: utf-8 -*-
"""
Windows日志分析工具 - 图形界面
基于PyQt5开发
"""

import sys
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QLabel, QFileDialog, QMessageBox, QProgressDialog,
    QGroupBox, QCheckBox, QDateTimeEdit, QLineEdit,
    QTabWidget, QSplitter, QTextEdit, QHeaderView,
    QFrame, QGridLayout, QSpacerItem, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt5.QtGui import QFont, QColor, QBrush

from event_categories import EVENT_CATEGORIES, get_category_names, get_event_description
from log_parser import WindowsLogParser, filter_events


class LoadLogThread(QThread):
    """后台加载日志线程，防止UI卡顿"""
    finished = pyqtSignal(list, str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)
    
    def __init__(self, load_type, source, log_type="System", hours_back=24):
        super().__init__()
        self.load_type = load_type  # 'local' or 'file'
        self.source = source
        self.log_type = log_type
        self.hours_back = hours_back
    
    def run(self):
        try:
            if self.load_type == 'local':
                events = WindowsLogParser.read_local_log(
                    log_type=self.log_type,
                    max_records=200000,
                    hours_back=self.hours_back
                )
                self.finished.emit(events, f"本机 {self.log_type} 日志")
            else:  # file
                events = WindowsLogParser.parse_evtx_file(self.source)
                self.finished.emit(events, os.path.basename(self.source))
        except Exception as e:
            self.error.emit(str(e))


class WindowsLogAnalyzer(QMainWindow):
    """主窗口"""
    
    def __init__(self):
        super().__init__()
        self.current_events = []
        self.filtered_events = []
        self.current_hours_back = None
        self.setWindowTitle("Windows 日志分析工具 v1.0")
        self.setGeometry(100, 100, 1400, 800)
        self.init_ui()
    
    def init_ui(self):
        """初始化界面"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # === 顶部工具栏 ===
        toolbar = QHBoxLayout()
        
        # 加载方式
        self.load_combo = QComboBox()
        self.load_combo.addItems(["读取本机日志", "导入EVTX文件"])
        self.load_combo.currentIndexChanged.connect(self.on_load_mode_changed)
        toolbar.addWidget(QLabel("加载方式:"))
        toolbar.addWidget(self.load_combo)
        
        # 日志类型 (本机) - 中文显示
        self.log_type_combo = QComboBox()
        self.log_type_combo.addItems(["系统", "安全", "应用程序", "安装"])
        self.log_type_mapping = {"系统": "System", "安全": "Security", "应用程序": "Application", "安装": "Setup"}
        toolbar.addWidget(QLabel("日志类型:"))
        toolbar.addWidget(self.log_type_combo)
        
        # 加载按钮
        self.load_btn = QPushButton("📂 加载日志")
        self.load_btn.clicked.connect(self.load_logs)
        self.load_btn.setStyleSheet("QPushButton { font-weight: bold; padding: 5px 15px; }")
        toolbar.addWidget(self.load_btn)
        
        # 导出按钮
        self.export_btn = QPushButton("💾 导出结果")
        self.export_btn.clicked.connect(self.export_results)
        self.export_btn.setEnabled(False)
        toolbar.addWidget(self.export_btn)
        
        toolbar.addStretch()
        
        # 状态标签
        self.status_label = QLabel("就绪")
        toolbar.addWidget(self.status_label)
        
        main_layout.addLayout(toolbar)
        
        # === 筛选面板 ===
        filter_group = QGroupBox("🔍 筛选条件")
        filter_layout = QGridLayout()
        
        # 行0: 分类筛选
        filter_layout.addWidget(QLabel("事件分类:"), 0, 0)
        self.category_combo = QComboBox()
        categories = ["全部"] + get_category_names()
        self.category_combo.addItems(categories)
        # 不再直接连接，由查询按钮统一触发
        filter_layout.addWidget(self.category_combo, 0, 1)
        
        filter_layout.addWidget(QLabel("自定义ID:"), 0, 2)
        self.custom_ids_edit = QLineEdit()
        self.custom_ids_edit.setPlaceholderText("如: 4624,4625,4672")
        # 不再直接连接，由查询按钮统一触发
        filter_layout.addWidget(self.custom_ids_edit, 0, 3)
        
        # 行1: 时间范围
        filter_layout.addWidget(QLabel("开始时间:"), 1, 0)
        self.start_time_edit = QDateTimeEdit()
        self.start_time_edit.setDateTime(QDateTime.currentDateTime().addDays(-1))
        self.start_time_edit.setCalendarPopup(True)
        # 不再直接连接，由查询按钮统一触发
        filter_layout.addWidget(self.start_time_edit, 1, 1)
        
        filter_layout.addWidget(QLabel("结束时间:"), 1, 2)
        self.end_time_edit = QDateTimeEdit()
        self.end_time_edit.setDateTime(QDateTime.currentDateTime())
        self.end_time_edit.setCalendarPopup(True)
        # 不再直接连接，由查询按钮统一触发
        filter_layout.addWidget(self.end_time_edit, 1, 3)
        
        # 行2: 关键词搜索 + 按钮
        filter_layout.addWidget(QLabel("关键词:"), 2, 0)
        self.keyword_edit = QLineEdit()
        self.keyword_edit.setPlaceholderText("在事件消息中搜索...")
        # 不再直接连接，由查询按钮统一触发
        filter_layout.addWidget(self.keyword_edit, 2, 1, 1, 2)
        
        # 查询按钮
        self.query_btn = QPushButton("🔍 查询")
        self.query_btn.clicked.connect(self.query_logs)
        filter_layout.addWidget(self.query_btn, 2, 3)
        
        # 清除筛选按钮
        self.clear_filter_btn = QPushButton("🔄 清除筛选")
        self.clear_filter_btn.clicked.connect(self.clear_filters)
        filter_layout.addWidget(self.clear_filter_btn, 2, 4)
        
        filter_group.setLayout(filter_layout)
        main_layout.addWidget(filter_group)
        
        # === 主内容区域 (表格 + 详情) ===
        splitter = QSplitter(Qt.Vertical)
        
        # 表格 - 共8列
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "时间", "事件ID", "事件说明", "日志类型", "来源", "计算机", "分类", "消息摘要"
        ])
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        self.table.itemClicked.connect(self.on_table_item_clicked)
        splitter.addWidget(self.table)
        
        # 详情区域
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.addWidget(QLabel("📋 事件详情"))
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Consolas", 10))
        detail_layout.addWidget(self.detail_text)
        splitter.addWidget(detail_widget)
        
        # 设置分割比例
        splitter.setSizes([500, 200])
        main_layout.addWidget(splitter)
        
        # === 统计信息栏 ===
        stat_layout = QHBoxLayout()
        self.stat_label = QLabel("总事件: 0 | 筛选后: 0")
        stat_layout.addWidget(self.stat_label)
        stat_layout.addStretch()
        main_layout.addLayout(stat_layout)
    
    def on_load_mode_changed(self, index):
        is_local = (index == 0)
        self.log_type_combo.setEnabled(is_local)
        # self.hours_combo 已移除，所以注释或删除这行
    
    def load_logs(self, hours_back=24):
        """加载日志，可指定时间范围（小时）"""
        load_mode = self.load_combo.currentIndex()
        if load_mode == 0:  # 本机日志
            log_type_text = self.log_type_combo.currentText()
            log_type = self.log_type_mapping.get(log_type_text, "System")
            self.current_hours_back = hours_back

            self.status_label.setText(f"正在加载本机 {log_type_text} 日志（最近{hours_back}小时）...")
            self.load_btn.setEnabled(False)

            self.thread = LoadLogThread('local', None, log_type, hours_back)
            self.thread.finished.connect(self.on_logs_loaded)
            self.thread.error.connect(self.on_load_error)
            self.thread.start()
        else:  # 导入EVTX文件
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择EVTX日志文件", "",
                "EVTX文件 (*.evtx);;所有文件 (*)"
            )
            if not file_path:
                return

            self.status_label.setText(f"正在解析 {os.path.basename(file_path)}...")
            self.load_btn.setEnabled(False)

            self.thread = LoadLogThread('file', file_path)
            self.thread.finished.connect(self.on_logs_loaded)
            self.thread.error.connect(self.on_load_error)
            self.thread.start()
    
    def on_logs_loaded(self, events, source_name):
        self.load_btn.setEnabled(True)
        self.current_events = events
        self.status_label.setText(f"✅ 已加载 {len(events)} 条事件 (来源: {source_name})")
        self.export_btn.setEnabled(True)
        # 不再自动设置筛选时间范围，因为加载时已经按范围读取了
        self.apply_filters()  # 应用其他筛选条件（如分类、关键词等）
    def query_logs(self):
        """根据面板时间范围重新加载日志"""
        # 获取开始和结束时间
        start = self.start_time_edit.dateTime().toPyDateTime()
        end = self.end_time_edit.dateTime().toPyDateTime()
        if start >= end:
            QMessageBox.warning(self, "提示", "开始时间必须早于结束时间")
            return
        delta = end - start
        # 计算小时数（向上取整，至少1小时）
        hours = max(1, int(delta.total_seconds() / 3600) + 1)
        # 重新加载日志，使用计算的小时数
        self.load_logs(hours_back=hours)

    def on_load_error(self, error_msg):
        self.load_btn.setEnabled(True)
        self.status_label.setText("❌ 加载失败")
        QMessageBox.critical(self, "错误", f"加载日志失败:\n{error_msg}")
    
    def apply_filters(self):
        """应用筛选条件（由查询按钮触发）"""
        if not self.current_events:
            QMessageBox.information(self, "提示", "请先加载日志")
            return
        
        # 获取筛选条件
        category = self.category_combo.currentText()
        if category == "全部":
            category = None
        
        # 解析自定义事件ID
        custom_ids = []
        ids_text = self.custom_ids_edit.text().strip()
        if ids_text:
            try:
                custom_ids = [int(x.strip()) for x in ids_text.split(',') if x.strip()]
            except ValueError:
                pass
        
        # 时间范围
        start_time = self.start_time_edit.dateTime().toPyDateTime()
        end_time = self.end_time_edit.dateTime().toPyDateTime()
        
        # 关键词
        keyword = self.keyword_edit.text().strip()
        if not keyword:
            keyword = None
        
        # 执行筛选
        self.filtered_events = filter_events(
            self.current_events,
            category=category,
            event_ids=custom_ids if custom_ids else None,
            start_time=start_time,
            end_time=end_time,
            keyword=keyword
        )
        
        # 更新表格
        self.update_table()
        
        # 更新统计
        total = len(self.current_events)
        filtered = len(self.filtered_events)
        self.stat_label.setText(f"总事件: {total} | 筛选后: {filtered}")
        self.status_label.setText(f"✅ 筛选完成，共 {filtered} 条记录")
    
    def clear_filters(self):
        """清除所有筛选条件，并重置时间范围为最近24小时"""
        self.category_combo.setCurrentIndex(0)
        self.custom_ids_edit.clear()
        self.keyword_edit.clear()
        now = QDateTime.currentDateTime()
        self.start_time_edit.setDateTime(now.addSecs(-24 * 3600))
        self.end_time_edit.setDateTime(now)
        # 不清除数据，也不自动加载，让用户手动点击“查询”来重新加载
        # 如果希望自动重新加载，可调用 self.query_logs()
    
    def update_table(self):
        """更新表格显示（包含事件说明列）"""
        self.table.setRowCount(0)
        
        if not self.filtered_events:
            return
        
        from event_categories import get_category_by_event_id, get_event_description
        
        self.table.setRowCount(len(self.filtered_events))
        
        for row, event in enumerate(self.filtered_events):
            # 时间
            time_obj = event.get('TimeGenerated')
            time_str = time_obj.strftime("%Y-%m-%d %H:%M:%S") if time_obj else "未知"
            self.table.setItem(row, 0, QTableWidgetItem(time_str))
            
            # 事件ID
            eid = event.get('EventID', 0)
            eid_item = QTableWidgetItem(str(eid))
            if eid in [41, 6008, 1001]:
                eid_item.setForeground(QBrush(QColor(255, 0, 0)))
            elif eid in [4625, 4740]:
                eid_item.setForeground(QBrush(QColor(255, 165, 0)))
            self.table.setItem(row, 1, eid_item)
            
            # 事件说明
            desc = get_event_description(eid)
            self.table.setItem(row, 2, QTableWidgetItem(desc))
            
            # 日志类型
            log_type = event.get('LogTypeDisplay', event.get('LogType', ''))
            self.table.setItem(row, 3, QTableWidgetItem(log_type))
            
            # 来源
            source = event.get('SourceName', '')
            self.table.setItem(row, 4, QTableWidgetItem(source[:30]))
            
            # 计算机
            computer = event.get('ComputerName', '')
            self.table.setItem(row, 5, QTableWidgetItem(computer[:20]))
            
            # 分类
            category = get_category_by_event_id(eid, event.get('LogType', 'System'))
            self.table.setItem(row, 6, QTableWidgetItem(category))
            
            # 消息摘要
            msg = event.get('Message', '')
            if len(msg) > 100:
                msg = msg[:100] + "..."
            self.table.setItem(row, 7, QTableWidgetItem(msg))
        
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
    
    def on_table_item_clicked(self, item):
        row = item.row()
        if row < len(self.filtered_events):
            event = self.filtered_events[row]
            self.show_event_detail(event)
    
    def show_event_detail(self, event):
        detail = []
        detail.append("=" * 60)
        detail.append(f"事件ID: {event.get('EventID', 'N/A')}")
        detail.append(f"时间: {event.get('TimeGenerated', 'N/A')}")
        detail.append(f"日志类型: {event.get('LogTypeDisplay', event.get('LogType', 'N/A'))}")
        detail.append(f"来源: {event.get('SourceName', 'N/A')}")
        detail.append(f"计算机: {event.get('ComputerName', 'N/A')}")
        detail.append(f"用户: {event.get('User', 'N/A')}")
        detail.append("-" * 60)
        detail.append("消息:")
        detail.append(event.get('Message', '无详细信息'))
        
        event_data = event.get('EventData', {})
        if event_data:
            detail.append("-" * 60)
            detail.append("事件数据:")
            for key, value in event_data.items():
                if value:
                    detail.append(f"  {key}: {value}")
        
        detail.append("=" * 60)
        self.detail_text.setText("\n".join(detail))
    
    def export_results(self):
        if not self.filtered_events:
            QMessageBox.information(self, "提示", "没有数据可导出")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存筛选结果", "",
            "JSON文件 (*.json);;CSV文件 (*.csv);;文本文件 (*.txt)"
        )
        if not file_path:
            return
        
        try:
            import json
            export_data = []
            for event in self.filtered_events:
                e = event.copy()
                if e.get('TimeGenerated'):
                    e['TimeGenerated'] = e['TimeGenerated'].isoformat()
                export_data.append(e)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            QMessageBox.information(self, "成功", f"已导出 {len(export_data)} 条事件到:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败:\n{str(e)}")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = WindowsLogAnalyzer()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
