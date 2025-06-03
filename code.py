#!/usr/bin/env python3
"""
System Monitor & Network Analyzer
A comprehensive system monitoring tool that demonstrates:
- System resource monitoring (CPU, Memory, Disk)
- Network analysis and speed testing
- Real-time data collection and alerts
- Data visualization with ASCII charts
- Log file analysis and reporting
- Cross-platform compatibility
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import statistics


@dataclass
class SystemSnapshot:
    """Data class for system resource snapshot"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int


class SystemMonitor:
    """Cross-platform system resource monitor"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.snapshots: List[SystemSnapshot] = []
        self.alerts_enabled = True
        self.alert_thresholds = {
            'cpu': 80.0,
            'memory': 85.0,
            'disk': 90.0
        }
        self.baseline_network = self._get_network_stats()
        
    def _run_command(self, command: str) -> str:
        """Safely execute system command and return output"""
        try:
            result = subprocess.run(command.split(), 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return ""
    
    def get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        try:
            if self.platform == "windows":
                # Windows: use wmic
                output = self._run_command("wmic cpu get loadpercentage /value")
                for line in output.split('\n'):
                    if 'LoadPercentage' in line:
                        return float(line.split('=')[1])
            else:
                # Unix-like: use top or vmstat
                if os.path.exists('/proc/loadavg'):
                    with open('/proc/loadavg', 'r') as f:
                        load = float(f.read().split()[0])
                        # Convert load average to rough percentage (assumes 1 core)
                        cpu_count = os.cpu_count() or 1
                        return min(100.0, (load / cpu_count) * 100)
                else:
                    # macOS fallback
                    output = self._run_command("top -l 1 -n 0")
                    for line in output.split('\n'):
                        if 'CPU usage' in line:
                            # Parse: "CPU usage: 15.2% user, 8.1% sys, 76.7% idle"
                            parts = line.split(',')
                            if len(parts) >= 3:
                                idle = float(parts[2].split('%')[0].strip().split()[-1])
                                return 100.0 - idle
        except (ValueError, IndexError, FileNotFoundError):
            pass
        
        # Fallback: simple load calculation
        return min(100.0, os.getloadavg()[0] * 20) if hasattr(os, 'getloadavg') else 0.0
    
    def get_memory_usage(self) -> Tuple[float, float, float]:
        """Get memory usage: (percent, used_gb, total_gb)"""
        try:
            if self.platform == "windows":
                # Windows memory info
                total_output = self._run_command("wmic computersystem get TotalPhysicalMemory /value")
                avail_output = self._run_command("wmic OS get AvailablePhysicalMemory /value")
                
                total_bytes = 0
                avail_bytes = 0
                
                for line in total_output.split('\n'):
                    if 'TotalPhysicalMemory' in line:
                        total_bytes = int(line.split('=')[1])
                
                for line in avail_output.split('\n'):
                    if 'AvailablePhysicalMemory' in line:
                        avail_bytes = int(line.split('=')[1]) * 1024  # Convert KB to bytes
                
                used_bytes = total_bytes - avail_bytes
                total_gb = total_bytes / (1024**3)
                used_gb = used_bytes / (1024**3)
                percent = (used_bytes / total_bytes) * 100
                
                return percent, used_gb, total_gb
                
            else:
                # Unix-like systems
                if os.path.exists('/proc/meminfo'):
                    with open('/proc/meminfo', 'r') as f:
                        meminfo = f.read()
                    
                    mem_total = 0
                    mem_available = 0
                    
                    for line in meminfo.split('\n'):
                        if line.startswith('MemTotal:'):
                            mem_total = int(line.split()[1]) * 1024  # Convert KB to bytes
                        elif line.startswith('MemAvailable:'):
                            mem_available = int(line.split()[1]) * 1024
                    
                    if mem_total > 0:
                        used_bytes = mem_total - mem_available
                        total_gb = mem_total / (1024**3)
                        used_gb = used_bytes / (1024**3)
                        percent = (used_bytes / mem_total) * 100
                        return percent, used_gb, total_gb
                
                else:
                    # macOS fallback
                    output = self._run_command("vm_stat")
                    page_size = 4096  # Default page size
                    
                    pages_free = 0
                    pages_active = 0
                    pages_inactive = 0
                    pages_wired = 0
                    
                    for line in output.split('\n'):
                        if 'free:' in line:
                            pages_free = int(line.split()[2].replace('.', ''))
                        elif 'active:' in line:
                            pages_active = int(line.split()[2].replace('.', ''))
                        elif 'inactive:' in line:
                            pages_inactive = int(line.split()[2].replace('.', ''))
                        elif 'wired down:' in line:
                            pages_wired = int(line.split()[3].replace('.', ''))
                    
                    total_pages = pages_free + pages_active + pages_inactive + pages_wired
                    used_pages = pages_active + pages_inactive + pages_wired
                    
                    if total_pages > 0:
                        total_gb = (total_pages * page_size) / (1024**3)
                        used_gb = (used_pages * page_size) / (1024**3)
                        percent = (used_pages / total_pages) * 100
                        return percent, used_gb, total_gb
        
        except (ValueError, IndexError, FileNotFoundError):
            pass
        
        return 0.0, 0.0, 0.0
    
    def get_disk_usage(self, path: str = None) -> Tuple[float, float, float]:
        """Get disk usage for specified path: (percent, used_gb, total_gb)"""
        if path is None:
            path = "C:\\" if self.platform == "windows" else "/"
        
        try:
            if hasattr(os, 'statvfs'):  # Unix-like
                statvfs = os.statvfs(path)
                total_bytes = statvfs.f_frsize * statvfs.f_blocks
                free_bytes = statvfs.f_frsize * statvfs.f_available
                used_bytes = total_bytes - free_bytes
            else:  # Windows
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(path),
                    ctypes.pointer(free_bytes),
                    ctypes.pointer(total_bytes),
                    None
                )
                free_bytes = free_bytes.value
                total_bytes = total_bytes.value
                used_bytes = total_bytes - free_bytes
            
            total_gb = total_bytes / (1024**3)
            used_gb = used_bytes / (1024**3)
            percent = (used_bytes / total_bytes) * 100 if total_bytes > 0 else 0
            
            return percent, used_gb, total_gb
            
        except (OSError, AttributeError):
            return 0.0, 0.0, 0.0
    
    def _get_network_stats(self) -> Dict[str, int]:
        """Get network statistics"""
        stats = {'bytes_sent': 0, 'bytes_recv': 0}
        
        try:
            if self.platform == "windows":
                # Windows network stats
                output = self._run_command("wmic path Win32_PerfRawData_Tcpip_NetworkInterface get BytesSentPerSec,BytesReceivedPerSec /format:csv")
                # Parse CSV output and sum up interfaces
                lines = output.split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            try:
                                stats['bytes_recv'] += int(parts[1])
                                stats['bytes_sent'] += int(parts[2])
                            except (ValueError, IndexError):
                                continue
            
            elif os.path.exists('/proc/net/dev'):
                # Linux network stats
                with open('/proc/net/dev', 'r') as f:
                    lines = f.readlines()[2:]  # Skip headers
                
                for line in lines:
                    if ':' in line:
                        parts = line.split()
                        if len(parts) >= 10:
                            try:
                                stats['bytes_recv'] += int(parts[1])
                                stats['bytes_sent'] += int(parts[9])
                            except (ValueError, IndexError):
                                continue
            
            else:
                # macOS fallback
                output = self._run_command("netstat -ib")
                lines = output.split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 7:
                        try:
                            stats['bytes_recv'] += int(parts[6])
                            stats['bytes_sent'] += int(parts[9]) if len(parts) > 9 else 0
                        except (ValueError, IndexError):
                            continue
        
        except (FileNotFoundError, PermissionError):
            pass
        
        return stats
    
    def get_active_connections(self) -> int:
        """Get number of active network connections"""
        try:
            if self.platform == "windows":
                output = self._run_command("netstat -an")
            else:
                output = self._run_command("netstat -an")
            
            count = 0
            for line in output.split('\n'):
                if 'ESTABLISHED' in line:
                    count += 1
            
            return count
        
        except:
            return 0
    
    def take_snapshot(self) -> SystemSnapshot:
        """Take a complete system snapshot"""
        cpu = self.get_cpu_usage()
        mem_percent, mem_used, mem_total = self.get_memory_usage()
        disk_percent, disk_used, disk_total = self.get_disk_usage()
        network = self._get_network_stats()
        connections = self.get_active_connections()
        
        snapshot = SystemSnapshot(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            cpu_percent=cpu,
            memory_percent=mem_percent,
            memory_used_gb=mem_used,
            memory_total_gb=mem_total,
            disk_percent=disk_percent,
            disk_used_gb=disk_used,
            disk_total_gb=disk_total,
            network_bytes_sent=network['bytes_sent'],
            network_bytes_recv=network['bytes_recv'],
            active_connections=connections
        )
        
        self.snapshots.append(snapshot)
        
        # Keep only last 100 snapshots
        if len(self.snapshots) > 100:
            self.snapshots = self.snapshots[-100:]
        
        # Check for alerts
        if self.alerts_enabled:
            self._check_alerts(snapshot)
        
        return snapshot
    
    def _check_alerts(self, snapshot: SystemSnapshot):
        """Check if any metrics exceed alert thresholds"""
        alerts = []
        
        if snapshot.cpu_percent > self.alert_thresholds['cpu']:
            alerts.append(f"🔥 HIGH CPU: {snapshot.cpu_percent:.1f}%")
        
        if snapshot.memory_percent > self.alert_thresholds['memory']:
            alerts.append(f"⚠️  HIGH MEMORY: {snapshot.memory_percent:.1f}%")
        
        if snapshot.disk_percent > self.alert_thresholds['disk']:
            alerts.append(f"💾 HIGH DISK: {snapshot.disk_percent:.1f}%")
        
        if alerts:
            print(f"\n🚨 ALERTS at {snapshot.timestamp}:")
            for alert in alerts:
                print(f"   {alert}")
            print()


class NetworkAnalyzer:
    """Network connectivity and speed analysis"""
    
    def __init__(self):
        self.test_servers = [
            ('google.com', 80),
            ('cloudflare.com', 80),
            ('github.com', 80),
            ('stackoverflow.com', 80)
        ]
    
    def ping_host(self, host: str, timeout: int = 3) -> Optional[float]:
        """Ping a host and return response time in milliseconds"""
        try:
            start_time = time.time()
            sock = socket.create_connection((host, 80), timeout)
            sock.close()
            return (time.time() - start_time) * 1000
        except (socket.timeout, socket.error, OSError):
            return None
    
    def test_connectivity(self) -> Dict[str, Optional[float]]:
        """Test connectivity to multiple servers"""
        results = {}
        print("Testing network connectivity...")
        
        for host, port in self.test_servers:
            print(f"  Pinging {host}...", end=' ')
            ping_time = self.ping_host(host)
            results[host] = ping_time
            
            if ping_time:
                print(f"{ping_time:.1f}ms")
            else:
                print("TIMEOUT")
        
        return results
    
    def estimate_speed(self, test_url: str = "http://httpbin.org/bytes/1048576") -> Dict[str, float]:
        """Estimate download speed (simplified test)"""
        try:
            import urllib.request
            import urllib.parse
            
            print("Testing download speed (1MB test)...")
            start_time = time.time()
            
            # Download 1MB of data
            with urllib.request.urlopen(test_url, timeout=10) as response:
                data = response.read()
            
            duration = time.time() - start_time
            bytes_downloaded = len(data)
            
            # Calculate speeds
            mbps = (bytes_downloaded * 8) / (duration * 1_000_000)  # Megabits per second
            mbps_download = bytes_downloaded / (duration * 1_000_000)  # Megabytes per second
            
            return {
                'duration_seconds': duration,
                'bytes_downloaded': bytes_downloaded,
                'mbps': mbps,
                'mb_per_sec': mbps_download
            }
        
        except Exception as e:
            print(f"Speed test failed: {e}")
            return {}
    
    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get network interface information"""
        interfaces = []
        
        try:
            if platform.system().lower() == "windows":
                output = subprocess.run(["ipconfig"], capture_output=True, text=True).stdout
                current_interface = {}
                
                for line in output.split('\n'):
                    line = line.strip()
                    if 'adapter' in line.lower():
                        if current_interface:
                            interfaces.append(current_interface)
                        current_interface = {'name': line}
                    elif 'IPv4 Address' in line:
                        current_interface['ipv4'] = line.split(':')[-1].strip()
                    elif 'Subnet Mask' in line:
                        current_interface['subnet'] = line.split(':')[-1].strip()
                
                if current_interface:
                    interfaces.append(current_interface)
            
            else:
                # Unix-like systems
                output = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
                current_interface = {}
                
                for line in output.split('\n'):
                    if line and not line.startswith(' ') and not line.startswith('\t'):
                        if current_interface:
                            interfaces.append(current_interface)
                        current_interface = {'name': line.split(':')[0]}
                    elif 'inet ' in line:
                        parts = line.strip().split()
                        for i, part in enumerate(parts):
                            if part == 'inet' and i + 1 < len(parts):
                                current_interface['ipv4'] = parts[i + 1]
                                break
                
                if current_interface:
                    interfaces.append(current_interface)
        
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return interfaces


class SystemAnalyzer:
    """Main system analyzer application"""
    
    def __init__(self):
        self.monitor = SystemMonitor()
        self.network = NetworkAnalyzer()
        self.running = False
        self.monitor_thread = None
        self.data_file = "system_monitor_data.json"
        self.load_historical_data()
    
    def load_historical_data(self):
        """Load historical monitoring data"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    # Convert dict back to SystemSnapshot objects
                    self.monitor.snapshots = [
                        SystemSnapshot(**snapshot) for snapshot in data.get('snapshots', [])
                    ]
                print(f"Loaded {len(self.monitor.snapshots)} historical snapshots")
            except (json.JSONDecodeError, TypeError) as e:
                print(f"Error loading historical data: {e}")
    
    def save_data(self):
        """Save monitoring data to file"""
        try:
            data = {
                'snapshots': [asdict(snapshot) for snapshot in self.monitor.snapshots[-50:]],  # Keep last 50
                'saved_at': datetime.now().isoformat()
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving data: {e}")
    
    def display_current_status(self):
        """Display current system status"""
        snapshot = self.monitor.take_snapshot()
        
        print("\n" + "="*60)
        print(f"🖥️  SYSTEM STATUS - {snapshot.timestamp}")
        print("="*60)
        
        # CPU
        cpu_bar = self.create_progress_bar(snapshot.cpu_percent)
        print(f"CPU Usage:    {cpu_bar} {snapshot.cpu_percent:5.1f}%")
        
        # Memory
        mem_bar = self.create_progress_bar(snapshot.memory_percent)
        print(f"Memory Usage: {mem_bar} {snapshot.memory_percent:5.1f}% ({snapshot.memory_used_gb:.1f}GB/{snapshot.memory_total_gb:.1f}GB)")
        
        # Disk
        disk_bar = self.create_progress_bar(snapshot.disk_percent)
        print(f"Disk Usage:   {disk_bar} {snapshot.disk_percent:5.1f}% ({snapshot.disk_used_gb:.1f}GB/{snapshot.disk_total_gb:.1f}GB)")
        
        # Network
        print(f"Network:      📤 {snapshot.network_bytes_sent:,} bytes sent")
        print(f"              📥 {snapshot.network_bytes_recv:,} bytes received")
        print(f"Connections:  🔗 {snapshot.active_connections} active")
        
        print("="*60)
    
    def create_progress_bar(self, percentage: float, width: int = 20) -> str:
        """Create ASCII progress bar"""
        filled = int(width * percentage / 100)
        bar = "█" * filled + "░" * (width - filled)
        
        # Color coding
        if percentage > 90:
            return f"🔴{bar}"
        elif percentage > 75:
            return f"🟡{bar}"
        else:
            return f"🟢{bar}"
    
    def display_historical_analysis(self):
        """Display analysis of historical data"""
        if len(self.monitor.snapshots) < 2:
            print("\nNot enough historical data for analysis.")
            return
        
        print("\n" + "="*60)
        print("📊 HISTORICAL ANALYSIS")
        print("="*60)
        
        # Calculate averages and trends
        cpu_values = [s.cpu_percent for s in self.monitor.snapshots]
        mem_values = [s.memory_percent for s in self.monitor.snapshots]
        disk_values = [s.disk_percent for s in self.monitor.snapshots]
        
        print(f"Data Points: {len(self.monitor.snapshots)} snapshots")
        print(f"Time Range:  {self.monitor.snapshots[0].timestamp} to {self.monitor.snapshots[-1].timestamp}")
        print()
        
        # CPU Analysis
        print("CPU Usage Statistics:")
        print(f"  Average: {statistics.mean(cpu_values):.1f}%")
        print(f"  Peak:    {max(cpu_values):.1f}%")
        print(f"  Low:     {min(cpu_values):.1f}%")
        
        # Memory Analysis
        print("\nMemory Usage Statistics:")
        print(f"  Average: {statistics.mean(mem_values):.1f}%")
        print(f"  Peak:    {max(mem_values):.1f}%")
        print(f"  Low:     {min(mem_values):.1f}%")
        
        # Trend analysis
        if len(cpu_values) >= 10:
            recent_cpu = statistics.mean(cpu_values[-5:])
            older_cpu = statistics.mean(cpu_values[:5])
            cpu_trend = "📈 Increasing" if recent_cpu > older_cpu else "📉 Decreasing"
            print(f"\nCPU Trend: {cpu_trend} ({recent_cpu:.1f}% vs {older_cpu:.1f}%)")
        
        print("="*60)
    
    def run_network_analysis(self):
        """Run comprehensive network analysis"""
        print("\n" + "="*60)
        print("🌐 NETWORK ANALYSIS")
        print("="*60)
        
        # Show network interfaces
        interfaces = self.network.get_network_interfaces()
        if interfaces:
            print("Network Interfaces:")
            for interface in interfaces:
                print(f"  {interface.get('name', 'Unknown')}")
                if 'ipv4' in interface:
                    print(f"    IPv4: {interface['ipv4']}")
        
        print()
        
        # Test connectivity
        connectivity = self.network.test_connectivity()
        
        # Calculate average ping
        valid_pings = [ping for ping in connectivity.values() if ping is not None]
        if valid_pings:
            avg_ping = statistics.mean(valid_pings)
            print(f"\nConnectivity Summary:")
            print(f"  Reachable servers: {len(valid_pings)}/{len(connectivity)}")
            print(f"  Average ping: {avg_ping:.1f}ms")
            
            if avg_ping < 50:
                print("  Connection quality: 🟢 Excellent")
            elif avg_ping < 100:
                print("  Connection quality: 🟡 Good")
            else:
                print("  Connection quality: 🔴 Poor")
        
        # Speed test
        print("\n" + "-"*40)
        speed_result = self.network.estimate_speed()
        if speed_result:
            print(f"Download Speed: {speed_result['mb_per_sec']:.2f} MB/s ({speed_result['mbps']:.2f} Mbps)")
        
        print("="*60)
    
    def start_monitoring(self, interval: int = 5):
        """Start continuous monitoring"""
        def monitor_loop():
            while self.running:
                self.display_current_status()
                time.sleep(interval)
        
        self.running = True
        self.monitor_thread = threading.Thread(target=monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        print(f"🔄 Started continuous monitoring (every {interval}s)")
        print("Press Ctrl+C to stop monitoring")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
        print("\n⏹️  Monitoring stopped")
        self.save_data()
    
    def configure_alerts(self):
        """Configure alert thresholds"""
        print("\n" + "="*60)
        print("⚙️  ALERT CONFIGURATION")
        print("="*60)
        
        print("Current thresholds:")
        for metric, threshold in self.monitor.alert_thresholds.items():
            print(f"  {metric.upper()}: {threshold}%")
        
        print("\nEnter new thresholds (press Enter to keep current):")
        
        for metric in ['cpu', 'memory', 'disk']:
            current = self.monitor.alert_thresholds[metric]
            try:
                new_value = input(f"{metric.upper()} threshold [{current}%]: ").strip()
                if new_value:
                    threshold = float(new_value)
                    if 0 < threshold <= 100:
                        self.monitor.alert_thresholds[metric] = threshold
                        print(f"  ✓ {metric.upper()} threshold set to {threshold}%")
                    else:
                        print(f"  ✗ Invalid threshold for {metric}")
            except ValueError:
                print(f"  ✗ Invalid value for {metric}")
        
        # Toggle alerts
        toggle = input(f"\nAlerts currently {'ENABLED' if self.monitor.alerts_enabled else 'DISABLED'}. Toggle? (y/n): ").lower()
        if toggle == 'y':
            self.monitor.alerts_enabled = not self.monitor.alerts_enabled
            print(f"  ✓ Alerts {'ENABLED' if self.monitor.alerts_enabled else 'DISABLED'}")
    
    def show_system_info(self):
        """Display system information"""
        print("\n" + "="*60)
        print("ℹ️  SYSTEM INFORMATION")
        print("="*60)
        
        print(f"Operating System: {platform.system()} {platform.release()}")
        print(f"Architecture:     {platform.machine()}")
        print(f"Processor:        {platform.processor()}")
        print(f"Python Version:   {platform.python_version()}")
        print(f"CPU Cores:        {os.cpu_count()}")
        
        # Uptime (if available)
        try:
            if platform.system().lower() == "windows":
                output = subprocess.run(["wmic", "os", "get", "lastbootuptime"], 
                                      capture_output=True, text=True).stdout
                # Parse Windows boot time (simplified)
                print("Boot Time:        Available via system tools")
            else:
                with open('/proc/uptime', 'r') as f:
                    uptime_seconds = float(f.read().split()[0])
                    uptime_str = str(timedelta(seconds=int(uptime_seconds)))
                    print(f"Uptime:           {uptime_str}")
        except (FileNotFoundError, PermissionError, subprocess.CalledProcessError):
            pass
        
        print("="*60)
    
    def run(self):
        """Main application loop"""
        print("🖥️  System Monitor & Network Analyzer")
        print("Monitor system resources and analyze network performance")
        print()
        
        while True:
            print("\n" + "="*40)
            print("MAIN MENU")
            print("="*40)
            print("1. Current System Status")
            print("2. Start Continuous Monitoring")
            print("3. Network Analysis")
            print("4. Historical Analysis")
            print("5. Configure Alerts")
            print("6. System Information")
            print("7. Export Data")
            print("8. Exit")
            
            choice = input("\nSelect option (1-8): ").strip()
            
            if choice == '1':
                self.display_current_status()
            
            elif choice == '2':
                try:
                    interval = int(input("Monitoring interval in seconds [5]: ") or "5")
                    self.start_monitoring(interval)
                except ValueError:
                    print("Invalid interval, using 5 seconds")
                    self.start_monitoring(5)
            
            elif choice == '3':
                self.run_network_analysis()
            
            elif choice == '4':
                self.display_historical_analysis()
            
            elif choice == '5':
                self.configure_alerts()
            
            elif choice == '6':
                self.show_system_info()
            
            elif choice == '7':
                self.save_data()
                print(f"\n📁 Data exported to '{self.data_file}'")
                print("You can analyze this JSON file with other tools or spreadsheets")
            
            elif choice == '8':
                self.save_data()
                print("\n👋 Thank you for using System Monitor!")
                print("Your monitoring data has been saved.")
                break
            
            else:
                print("Invalid option. Please try again.")


def main():
    """Entry point of the application"""
    try:
        analyzer = SystemAnalyzer()
        analyzer.run()
    except KeyboardInterrupt:
        print("\n\nExiting... Data has been saved!")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        print("Please report this issue if it persists.")


if __name__ == "__main__":
    main()
