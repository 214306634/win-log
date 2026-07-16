# -*- coding: utf-8 -*-
"""
Windows事件日志解析模块
支持：读取本机日志(EVT) 和 导入EVTX文件
"""

import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

try:
    import win32evtlog
    import win32evtlogutil
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

import xml.etree.ElementTree as ET


class WindowsLogParser:
    """Windows事件日志解析器"""
    
    # 日志类型映射
    LOG_TYPES = {
        "Application": "应用程序",
        "System": "系统",
        "Security": "安全",
        "Setup": "安装",
        "ForwardedEvents": "转发事件"
    }

    @staticmethod
    def _extract_extra_fields(event_id, message, event_data=None):
        """根据事件ID提取额外字段（登录类型、源IP、进程信息等）"""
        extra = {}
        if event_id in (4624, 4625, 4672):  # 登录相关
            # 从消息文本中提取
            if message:
                # 提取 Logon Type
                match = re.search(r'Logon Type:\s*(\d+)', message)
                if match:
                    extra['LogonType'] = int(match.group(1))
                # 提取 Source Network Address
                match = re.search(r'Source Network Address:\s*([^\r\n]+)', message)
                if match:
                    extra['SourceIP'] = match.group(1).strip()
                # 提取 Account Name
                match = re.search(r'Account Name:\s*([^\r\n]+)', message)
                if match:
                    extra['AccountName'] = match.group(1).strip()
            # 如果传入了XML数据（用于EVTX）
            if event_data:
                if 'LogonType' in event_data:
                    extra['LogonType'] = int(event_data['LogonType'])
                if 'IpAddress' in event_data:
                    extra['SourceIP'] = event_data['IpAddress']
                if 'TargetUserName' in event_data:
                    extra['AccountName'] = event_data['TargetUserName']
        elif event_id == 4688:  # 进程创建
            if event_data:
                extra['ProcessId'] = event_data.get('ProcessId')
                extra['ParentProcessId'] = event_data.get('ParentProcessId')
                extra['CommandLine'] = event_data.get('CommandLine')
                extra['NewProcessName'] = event_data.get('NewProcessName')
        elif event_id == 4697:  # 服务安装
            if event_data:
                extra['ServiceName'] = event_data.get('ServiceName')
                extra['ServiceFileName'] = event_data.get('ServiceFileName')
        # 可继续扩展更多事件ID
        return extra

    @staticmethod
    def parse_evtx_file(file_path: str) -> List[Dict[str, Any]]:
        """
        解析EVTX文件
        使用python-evtx库
        """
        if not HAS_EVTX:
            raise ImportError("请安装 python-evtx: pip install python-evtx")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        events = []
        
        try:
            with Evtx(file_path) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        event_data = WindowsLogParser._parse_xml_event(xml_str)
                        if event_data:
                            events.append(event_data)
                    except Exception as e:
                        # 跳过无法解析的单条记录
                        continue
        except Exception as e:
            raise RuntimeError(f"解析EVTX文件失败: {str(e)}")
        
        return events
    
    @staticmethod
    def read_local_log(log_type: str = "System", 
                    max_records: int = 200000,
                    hours_back: int = 24) -> List[Dict[str, Any]]:
        """
        读取本机Windows事件日志（循环读取所有批次）
        """
        if not HAS_PYWIN32:
            raise ImportError("请安装 pywin32: pip install pywin32")

        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # 时间阈值
            time_threshold = None
            if hours_back > 0:
                time_threshold = datetime.now().timestamp() - (hours_back * 3600)

            total_read = 0
            while total_read < max_records:
                # 每次读取一批（默认约 1024 条）
                raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not raw_events:
                    break  # 没有更多事件了

                for event in raw_events:
                    if total_read >= max_records:
                        break

                    event_time = getattr(event, 'TimeGenerated', None)

                    # 时间过滤（跳过早于阈值的事件，但不 break，以防顺序错乱）
                    if event_time and time_threshold:
                        try:
                            ts = event_time.timestamp()
                            if ts < time_threshold:
                                continue
                        except:
                            pass

                    # 解析事件数据
                    event_data = {
                        'EventID': getattr(event, 'EventID', 0),
                        'TimeGenerated': event_time,
                        'SourceName': getattr(event, 'SourceName', ''),
                        'EventType': getattr(event, 'EventType', 0),
                        'EventCategory': getattr(event, 'EventCategory', 0),
                        'ComputerName': getattr(event, 'ComputerName', ''),
                        'User': getattr(event, 'User', ''),
                        'Message': '',
                        'LogType': log_type,
                        'LogTypeDisplay': WindowsLogParser.LOG_TYPES.get(log_type, log_type)
                    }
                    try:
                        event_data['Message'] = win32evtlogutil.SafeFormatMessage(event, log_type)
                    except:
                        event_data['Message'] = ''

                    # ----- 新增：提取额外字段 -----
                    extra = WindowsLogParser._extract_extra_fields(
                        event_data['EventID'], event_data['Message'], None
                    )
                    event_data['ExtraFields'] = extra
                    # -----------------------------

                    events.append(event_data)
                    total_read += 1

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            raise RuntimeError(f"读取本地日志失败: {str(e)}")

        return events
    
    @staticmethod
    def _parse_xml_event(xml_str: str) -> Optional[Dict[str, Any]]:
        """解析EVTX的XML格式事件"""
        try:
            root = ET.fromstring(xml_str)
            
            # 提取System部分
            system = root.find('.//System')
            if system is None:
                return None
            
            event_id_elem = system.find('EventID')
            event_id = int(event_id_elem.text) if event_id_elem is not None else 0
            
            # 提取时间
            time_created = system.find('TimeCreated')
            time_str = time_created.get('SystemTime') if time_created is not None else None
            
            # 提取Provider
            provider = system.find('Provider')
            source_name = provider.get('Name') if provider is not None else ''
            
            computer = system.find('Computer')
            computer_name = computer.text if computer is not None else ''
            
            # 提取EventData
            event_data_elem = root.find('.//EventData')
            event_data_dict = {}
            if event_data_elem is not None:
                for data in event_data_elem.findall('Data'):
                    name = data.get('Name', '')
                    if name:
                        event_data_dict[name] = data.text or ''
            
            # 提取Message (如果有)
            rendering_info = root.find('.//RenderingInfo')
            message = ''
            if rendering_info is not None:
                message_elem = rendering_info.find('.//Message')
                if message_elem is not None:
                    message = message_elem.text or ''
            
            # 构建事件对象
            event = {
                'EventID': event_id,
                'TimeGenerated': WindowsLogParser._parse_windows_time(time_str),
                'SourceName': source_name,
                'ComputerName': computer_name,
                'Message': message or str(event_data_dict),
                'EventData': event_data_dict,
                'LogType': 'EVTX',
                'LogTypeDisplay': '导入文件'
            }
            
            # ----- 新增：提取额外字段 -----
            extra = WindowsLogParser._extract_extra_fields(
                event_id, message, event_data_dict
            )
            event['ExtraFields'] = extra
            # -----------------------------

            return event
            
        except Exception as e:
            return None
    
    @staticmethod
    def _parse_windows_time(time_str: str) -> Optional[datetime]:
        """解析Windows时间格式"""
        if not time_str:
            return None
        try:
            # Windows时间格式: 2024-01-15T10:23:45.123Z
            if time_str.endswith('Z'):
                time_str = time_str[:-1]
            if '.' in time_str:
                dt = datetime.fromisoformat(time_str)
            else:
                dt = datetime.fromisoformat(time_str)
            return dt
        except:
            return None


def filter_events(events: List[Dict], 
                  category: Optional[str] = None,
                  event_ids: Optional[List[int]] = None,
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None,
                  keyword: Optional[str] = None,
                  logon_type: Optional[int] = None,
                  source_ip: Optional[str] = None) -> List[Dict]:
    """
    筛选事件（增加登录类型和源IP过滤）
    
    Args:
        events: 事件列表
        category: 事件分类名称 (来自EVENT_CATEGORIES)
        event_ids: 指定事件ID列表
        start_time: 开始时间
        end_time: 结束时间
        keyword: 关键词搜索 (在Message中)
        logon_type: 登录类型 (如 10 表示远程桌面)
        source_ip: 源IP地址 (支持部分匹配)
    """
    from event_categories import EVENT_CATEGORIES
    
    # 如果指定了分类，获取该分类下的所有事件ID
    target_ids = set()
    if category and category in EVENT_CATEGORIES:
        target_ids.update(EVENT_CATEGORIES[category]["event_ids"])
    
    # 如果额外指定了event_ids，合并
    if event_ids:
        target_ids.update(event_ids)
    
    result = []
    for event in events:
        # 分类筛选
        if target_ids:
            eid = event.get('EventID', 0)
            if eid not in target_ids:
                continue
        
        # 时间筛选
        if start_time or end_time:
            event_time = event.get('TimeGenerated')
            if event_time:
                if start_time and event_time < start_time:
                    continue
                if end_time and event_time > end_time:
                    continue
            else:
                # 没有时间信息的事件，在时间筛选时保留（或根据需求决定）
                pass
        
        # 关键词搜索
        if keyword:
            keyword_lower = keyword.lower()
            msg = event.get('Message', '').lower()
            if keyword_lower not in msg:
                # 也搜索EventData
                event_data = event.get('EventData', {})
                found = False
                for value in event_data.values():
                    if value and keyword_lower in str(value).lower():
                        found = True
                        break
                if not found:
                    continue

        # ----- 新增：登录类型筛选 -----
        if logon_type is not None:
            extra = event.get('ExtraFields', {})
            if extra.get('LogonType') != logon_type:
                continue
        
        # ----- 新增：源IP筛选 -----
        if source_ip:
            extra = event.get('ExtraFields', {})
            ip = extra.get('SourceIP', '')
            if source_ip.lower() not in ip.lower():
                continue
        
        result.append(event)
    
    return result
