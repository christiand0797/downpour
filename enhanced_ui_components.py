"""
Enhanced UI Components for Family Security Suite
Advanced widgets and visual elements for improved user experience
"""

import tkinter as tk
from tkinter import ttk
import math
import time
import threading
from datetime import datetime

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class CircularProgressBar:
    """Animated circular progress bar with neon effects"""
    
    def __init__(self, parent, size=100, width=15, 
                 bg_color='#0a0a15', fg_color='#00ffff',
                 text_color='#ffffff', font_size=12):
        self.parent = parent
        self.size = size
        self.width = width
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.text_color = text_color
        self.font_size = font_size
        self.value = 0
        self.target_value = 0
        self.animated = False
        
        # Create canvas
        self.canvas = tk.Canvas(parent, width=size, height=size,
                              bg=bg_color, highlightthickness=0)
        
        # Store canvas items
        self.bg_arc = None
        self.fg_arc = None
        self.text = None
        
        self._draw_progress(0)
    
    def _draw_progress(self, value):
        """Draw the circular progress"""
        self.canvas.delete("all")
        
        # Calculate angles
        extent = (value / 100) * 360
        
        # Background circle
        self.bg_arc = self.canvas.create_arc(
            self.width, self.width, 
            self.size - self.width, self.size - self.width,
            start=0, extent=360, 
            outline=self.bg_color, width=self.width,
            style='arc'
        )
        
        # Progress arc
        if value > 0:
            self.fg_arc = self.canvas.create_arc(
                self.width, self.width,
                self.size - self.width, self.size - self.width,
                start=90, extent=-extent,
                outline=self.fg_color, width=self.width,
                style='arc'
            )
        
        # Center text
        text = f"{value:.0f}%"
        self.text = self.canvas.create_text(
            self.size // 2, self.size // 2,
            text=text, fill=self.text_color,
            font=('Arial', self.font_size, 'bold')
        )
    
    def set_value(self, value, animated=True):
        """Set the progress value with optional animation"""
        self.target_value = max(0, min(100, value))
        
        if animated and not self.animated:
            self.animated = True
            threading.Thread(target=self._animate_progress, daemon=True).start()
        else:
            self.value = self.target_value
            self._draw_progress(self.value)
    
    def _animate_progress(self):
        """Animate progress change"""
        while self.animated and abs(self.value - self.target_value) > 0.5:
            diff = self.target_value - self.value
            step = diff / 10  # Smooth animation
            
            self.value += step
            self.parent.after(0, lambda: self._draw_progress(self.value))
            time.sleep(0.03)
        
        self.value = self.target_value
        self.parent.after(0, lambda: self._draw_progress(self.value))
        self.animated = False


class PerformanceGraph:
    """Real-time performance graph widget"""
    
    def __init__(self, parent, width=300, height=150, 
                 title="Performance", color='#00ffff'):
        self.parent = parent
        self.width = width
        self.height = height
        self.title = title
        self.color = color
        
        # Data storage
        self.data_points = []
        self.max_points = 60  # Show last 60 points (1 minute at 1-second intervals)
        
        # Create frame
        self.frame = tk.Frame(parent, bg='#0a0a15')
        
        # Title label
        self.title_label = tk.Label(
            self.frame, text=title,
            fg=color, bg='#0a0a15',
            font=('Arial', 10, 'bold')
        )
        self.title_label.pack(pady=(0, 5))
        
        # Canvas for graph
        self.canvas = tk.Canvas(
            self.frame, width=width, height=height,
            bg='#0a0a15', highlightthickness=0
        )
        self.canvas.pack()
        
        # Start animation
        self.animate = True
        threading.Thread(target=self._animation_loop, daemon=True).start()
    
    def add_data_point(self, value):
        """Add a new data point to the graph"""
        self.data_points.append(value)
        if len(self.data_points) > self.max_points:
            self.data_points.pop(0)
    
    def _draw_graph(self):
        """Draw the graph on canvas"""
        self.canvas.delete("all")
        
        if len(self.data_points) < 2:
            return
        
        # Calculate coordinates
        x_step = self.width / (self.max_points - 1)
        points = []
        
        for i, value in enumerate(self.data_points):
            x = i * x_step
            y = self.height - (value / 100) * self.height
            points.extend([x, y])
        
        # Draw grid lines
        for i in range(0, 101, 25):
            y = self.height - (i / 100) * self.height
            self.canvas.create_line(
                0, y, self.width, y,
                fill='#1a1a35', width=1
            )
            
            # Grid labels
            self.canvas.create_text(
                15, y, text=f"{i}%",
                fill='#666688', font=('Arial', 7)
            )
        
        # Draw the graph line
        if len(points) >= 4:
            self.canvas.create_line(
                points, fill=self.color, width=2,
                smooth=True, splinesteps=10
            )
        
        # Draw current value indicator
        if self.data_points:
            current_value = self.data_points[-1]
            current_x = (len(self.data_points) - 1) * x_step
            current_y = self.height - (current_value / 100) * self.height
            
            # Glow effect
            for i in range(3, 0, -1):
                glow_color = self._adjust_brightness(self.color, 0.3 / i)
                self.canvas.create_oval(
                    current_x - i * 2, current_y - i * 2,
                    current_x + i * 2, current_y + i * 2,
                    fill='', outline=glow_color, width=1
                )
            
            # Center dot
            self.canvas.create_oval(
                current_x - 3, current_y - 3,
                current_x + 3, current_y + 3,
                fill=self.color, outline=''
            )
            
            # Value label
            self.canvas.create_text(
                current_x, current_y - 15,
                text=f"{current_value:.1f}%",
                fill=self.color, font=('Arial', 8, 'bold')
            )
    
    def _adjust_brightness(self, color, factor):
        """Adjust color brightness for glow effects"""
        # Simple brightness adjustment for hex colors
        if color.startswith('#'):
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            
            r = min(255, int(r + (255 - r) * factor))
            g = min(255, int(g + (255 - g) * factor))
            b = min(255, int(b + (255 - b) * factor))
            
            return f'#{r:02x}{g:02x}{b:02x}'
        return color
    
    def _animation_loop(self):
        """Animation loop for real-time updates"""
        while self.animate:
            try:
                if self.data_points:
                    self.parent.after(0, self._draw_graph)
                time.sleep(0.5)
            except Exception:
                break
    
    def cleanup(self):
        """Cleanup animation resources"""
        self.animate = False


class ThreatLevelIndicator:
    """Dynamic threat level indicator with animations"""
    
    def __init__(self, parent, size=80):
        self.parent = parent
        self.size = size
        self.current_level = "low"
        self.target_level = "low"
        self.animation_progress = 0
        
        # Color schemes for threat levels
        self.colors = {
            'low': '#00ff9f',
            'medium': '#ffaa00', 
            'high': '#ff6600',
            'critical': '#ff0044'
        }
        
        # Create canvas
        self.canvas = tk.Canvas(
            parent, width=size, height=size,
            bg='#0a0a15', highlightthickness=0
        )
        
        # Start animation
        self.animate = True
        threading.Thread(target=self._animation_loop, daemon=True).start()
        
        self._draw_indicator("low")
    
    def set_threat_level(self, level):
        """Set the threat level with animation"""
        if level in self.colors and level != self.target_level:
            self.target_level = level
            self.animation_progress = 0
    
    def _draw_indicator(self, level):
        """Draw the threat level indicator"""
        self.canvas.delete("all")
        
        color = self.colors.get(level, '#00ff9f')
        center = self.size // 2
        radius = self.size // 3
        
        # Outer ring
        self.canvas.create_oval(
            center - radius - 5, center - radius - 5,
            center + radius + 5, center + radius + 5,
            outline='', fill='#0a0a15'
        )
        
        # Main circle with gradient effect
        for i in range(radius, 0, -2):
            brightness = 1 - (i / radius) * 0.5
            adjusted_color = self._adjust_color_brightness(color, brightness)
            self.canvas.create_oval(
                center - i, center - i,
                center + i, center + i,
                outline='', fill=adjusted_color
            )
        
        # Inner circle
        inner_radius = radius // 2
        self.canvas.create_oval(
            center - inner_radius, center - inner_radius,
            center + inner_radius, center + inner_radius,
            outline='', fill='#0a0a15'
        )
        
        # Threat level text
        self.canvas.create_text(
            center, center,
            text=level.upper(),
            fill=color, font=('Arial', 10, 'bold')
        )
        
        # Pulse animation
        if self.animation_progress < 50:
            pulse_radius = radius + (self.animation_progress % 20)
            pulse_alpha = 1 - (self.animation_progress % 20) / 20
            if pulse_alpha > 0:
                pulse_color = self._adjust_color_brightness(color, pulse_alpha)
                self.canvas.create_oval(
                    center - pulse_radius, center - pulse_radius,
                    center + pulse_radius, center + pulse_radius,
                    outline=pulse_color, width=2
                )
    
    def _adjust_color_brightness(self, color, brightness):
        """Adjust color brightness"""
        if color.startswith('#'):
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            
            r = min(255, int(r * brightness))
            g = min(255, int(g * brightness))
            b = min(255, int(b * brightness))
            
            return f'#{r:02x}{g:02x}{b:02x}'
        return color
    
    def _animation_loop(self):
        """Animation loop for threat level transitions"""
        while self.animate:
            try:
                if self.current_level != self.target_level:
                    self.animation_progress += 5
                    
                    if self.animation_progress >= 100:
                        self.current_level = self.target_level
                        self.animation_progress = 0
                    
                    self.parent.after(0, lambda: self._draw_indicator(self.target_level))
                else:
                    self.parent.after(0, lambda: self._draw_indicator(self.current_level))
                    time.sleep(0.1)
                    self.animation_progress = (self.animation_progress + 5) % 100
                
                time.sleep(0.05)
            except Exception:
                break
    
    def cleanup(self):
        """Cleanup animation resources"""
        self.animate = False


class StatusPanel:
    """Animated status panel with multiple metrics"""
    
    def __init__(self, parent, width=400, height=200):
        self.parent = parent
        self.width = width
        self.height = height
        
        # Create main frame
        self.frame = tk.Frame(parent, bg='#0a0a15')
        
        # Header
        self.header = tk.Label(
            self.frame, text="SYSTEM STATUS",
            fg='#00ffff', bg='#0a0a15',
            font=('Arial', 12, 'bold')
        )
        self.header.pack(pady=(10, 20))
        
        # Status grid
        self.status_frame = tk.Frame(self.frame, bg='#0a0a15')
        self.status_frame.pack()
        
        # Status indicators
        self.statuses = {}
        self._create_status_indicators()
        
        # Start update thread
        self.update_active = True
        threading.Thread(target=self._update_loop, daemon=True).start()
    
    def _create_status_indicators(self):
        """Create status indicator widgets"""
        indicators = [
            ('antivirus', '🛡️', 'Protection'),
            ('firewall', '🔥', 'Firewall'),
            ('network', '🌐', 'Network'),
            ('system', '⚙️', 'System'),
            ('ai', '🤖', 'AI Engine'),
            ('monitoring', '📊', 'Monitoring')
        ]
        
        for i, (key, icon, label) in enumerate(indicators):
            row = i // 3
            col = i % 3
            
            # Status frame
            status_frame = tk.Frame(self.status_frame, bg='#151528', relief='raised', bd=1)
            status_frame.grid(row=row, column=col, padx=10, pady=5)
            
            # Icon and label
            icon_label = tk.Label(
                status_frame, text=icon,
                fg='#8888aa', bg='#151528',
                font=('Arial', 16)
            )
            icon_label.pack(pady=(5, 0))
            
            text_label = tk.Label(
                status_frame, text=label,
                fg='#8888aa', bg='#151528',
                font=('Arial', 8)
            )
            text_label.pack()
            
            # Status indicator
            status_canvas = tk.Canvas(
                status_frame, width=20, height=20,
                bg='#151528', highlightthickness=0
            )
            status_canvas.pack(pady=5)
            
            # Draw initial status
            status_canvas.create_oval(
                5, 5, 15, 15,
                fill='#00ff9f', outline=''
            )
            
            self.statuses[key] = {
                'frame': status_frame,
                'canvas': status_canvas,
                'status': 'active'
            }
    
    def update_status(self, key, status, message=""):
        """Update status for a specific component"""
        if key not in self.statuses:
            return
        
        status_info = self.statuses[key]
        canvas = status_info['canvas']
        
        # Color mapping
        colors = {
            'active': '#00ff9f',
            'warning': '#ffaa00',
            'error': '#ff0044',
            'inactive': '#444466'
        }
        
        color = colors.get(status, '#444466')
        
        # Update indicator
        canvas.delete("all")
        canvas.create_oval(
            5, 5, 15, 15,
            fill=color, outline=''
        )
        
        # Update frame background if error
        if status == 'error':
            status_info['frame'].configure(bg='#2a1515')
        elif status == 'warning':
            status_info['frame'].configure(bg='#2a2a15')
        else:
            status_info['frame'].configure(bg='#151528')
        
        status_info['status'] = status
    
    def _update_loop(self):
        """Background update loop"""
        while self.update_active:
            try:
                if PSUTIL_AVAILABLE:
                    # Update system status based on actual metrics
                    cpu_percent = psutil.cpu_percent(interval=0.1)
                    memory = psutil.virtual_memory()
                    
                    if cpu_percent > 90 or memory.percent > 90:
                        self.update_status('system', 'warning')
                    else:
                        self.update_status('system', 'active')
                
                time.sleep(5)
            except Exception:
                time.sleep(10)
    
    def cleanup(self):
        """Cleanup update thread"""
        self.update_active = False


# Test the enhanced UI components
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Enhanced UI Components Test")
    root.configure(bg='#050508')
    
    # Test circular progress bar
    progress_frame = tk.Frame(root, bg='#050508')
    progress_frame.pack(pady=10)
    
    tk.Label(progress_frame, text="Circular Progress Test", 
           fg='#00ffff', bg='#050508', font=('Arial', 12, 'bold')).pack()
    
    progress = CircularProgressBar(progress_frame, size=100, fg_color='#00ff9f')
    progress.canvas.pack()
    progress.set_value(75)
    
    # Test performance graph
    graph_frame = tk.Frame(root, bg='#050508')
    graph_frame.pack(pady=10)
    
    graph = PerformanceGraph(graph_frame, title="CPU Usage", color='#ff00ff')
    graph.frame.pack()
    
    # Test threat indicator
    threat_frame = tk.Frame(root, bg='#050508')
    threat_frame.pack(pady=10)
    
    tk.Label(threat_frame, text="Threat Level Test",
           fg='#00ffff', bg='#050508', font=('Arial', 12, 'bold')).pack()
    
    threat = ThreatLevelIndicator(threat_frame)
    threat.canvas.pack()
    
    # Test status panel
    status = StatusPanel(root)
    status.frame.pack(pady=20)
    
    # Animate components
    def animate_test():
        import random
        # Update progress
        progress.set_value(random.randint(20, 100))
        
        # Update graph
        graph.add_data_point(random.randint(30, 90))
        
        # Update threat level
        levels = ['low', 'medium', 'high', 'critical']
        threat.set_threat_level(random.choice(levels))
        
        root.after(2000, animate_test)
    
    animate_test()
    
    root.mainloop()