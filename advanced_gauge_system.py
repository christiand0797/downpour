#!/usr/bin/env python3
"""
Advanced Gauge System v29
Advanced Gauge System for Hardware Performance
Responsive, animated gauges with real-time data visualization
"""
__version__ = "29.0.0"
import logging
_log = logging.getLogger(__name__)
_log.info("Advanced Gauge System loaded (v29)")

import tkinter as tk
from tkinter import ttk, Canvas
import math
import time
import threading
import queue
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import colorsys
from advanced_hardware_monitor import AdvancedHardwareMonitor, HardwareMetrics, GaugeConfiguration

class GaugeType(Enum):
    """Gauge types"""
    CIRCULAR = "circular"
    LINEAR = "linear"
    SEMICIRCULAR = "semicircular"
    DIGITAL = "digital"
    METER = "meter"
    PROGRESS = "progress"

class AnimationType(Enum):
    """Animation types"""
    SMOOTH = "smooth"
    BOUNCE = "bounce"
    ELASTIC = "elastic"
    PULSE = "pulse"
    GLOW = "glow"

@dataclass
class GaugeStyle:
    """Gauge styling configuration"""
    primary_color: str = "#00ff00"
    secondary_color: str = "#ff0000"
    background_color: str = "#1a1a1a"
    text_color: str = "#ffffff"
    border_color: str = "#333333"
    glow_color: str = "#00ff00"
    font_family: str = "Arial"
    font_size: int = 12
    show_labels: bool = True
    show_values: bool = True
    show_trends: bool = True
    show_predictions: bool = True
    animation_type: AnimationType = AnimationType.SMOOTH
    animation_speed: float = 0.1
    glow_enabled: bool = True
    gradient_enabled: bool = True

class AdvancedGauge:
    """Advanced gauge with responsive animations and real-time updates"""
    
    def __init__(self, canvas: Canvas, x: int, y: int, width: int, height: int,
                 gauge_type: GaugeType = GaugeType.CIRCULAR,
                 style: Optional[GaugeStyle] = None,
                 title: str = "Performance"):
        self.canvas = canvas
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.gauge_type = gauge_type
        self.style = style or GaugeStyle()
        self.title = title
        
        # Animation state
        self.current_value = 0.0
        self.target_value = 0.0
        self.animation_progress = 0.0
        self.animation_thread = None
        self.is_animating = False
        
        # Visual elements
        self.elements = {}
        self.colors = {}
        self.animation_queue = queue.Queue()
        
        # Performance data
        self.history = []
        self.trend_data = []
        self.predicted_value = 0.0
        self.velocity = 0.0
        
        # Create gauge
        self.create_gauge()
    
    def create_gauge(self):
        """Create gauge based on type"""
        if self.gauge_type == GaugeType.CIRCULAR:
            self.create_circular_gauge()
        elif self.gauge_type == GaugeType.LINEAR:
            self.create_linear_gauge()
        elif self.gauge_type == GaugeType.SEMICIRCULAR:
            self.create_semicircular_gauge()
        elif self.gauge_type == GaugeType.DIGITAL:
            self.create_digital_gauge()
        elif self.gauge_type == GaugeType.METER:
            self.create_meter_gauge()
        elif self.gauge_type == GaugeType.PROGRESS:
            self.create_progress_gauge()
    
    def create_circular_gauge(self):
        """Create circular gauge"""
        center_x = self.x + self.width // 2
        center_y = self.y + self.height // 2
        radius = min(self.width, self.height) // 2 - 20
        
        # Background circle
        self.elements['background'] = self.canvas.create_oval(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            fill=self.style.background_color,
            outline=self.style.border_color,
            width=2
        )
        
        # Gauge arc (will be updated)
        self.elements['gauge_arc'] = self.canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=90, extent=0,
            fill="", outline=self.style.primary_color,
            width=8, style=tk.ARC
        )
        
        # Center text
        self.elements['value_text'] = self.canvas.create_text(
            center_x, center_y,
            text="0.0%",
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size + 4, "bold")
        )
        
        # Title
        self.elements['title'] = self.canvas.create_text(
            center_x, center_y - radius - 10,
            text=self.title,
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size)
        )
        
        # Trend indicator
        if self.style.show_trends:
            self.elements['trend'] = self.canvas.create_text(
                center_x, center_y + radius + 10,
                text="→",
                fill=self.style.text_color,
                font=(self.style.font_family, self.style.font_size - 2)
            )
        
        # Prediction indicator
        if self.style.show_predictions:
            self.elements['prediction'] = self.canvas.create_text(
                center_x + radius + 10, center_y,
                text="",
                fill=self.style.glow_color,
                font=(self.style.font_family, self.style.font_size - 2)
            )
    
    def create_linear_gauge(self):
        """Create linear gauge"""
        # Background bar
        self.elements['background'] = self.canvas.create_rectangle(
            self.x + 10, self.y + self.height // 2 - 10,
            self.x + self.width - 10, self.y + self.height // 2 + 10,
            fill=self.style.background_color,
            outline=self.style.border_color,
            width=2
        )
        
        # Progress bar (will be updated)
        self.elements['progress'] = self.canvas.create_rectangle(
            self.x + 10, self.y + self.height // 2 - 10,
            self.x + 10, self.y + self.height // 2 + 10,
            fill=self.style.primary_color,
            outline=""
        )
        
        # Value text
        self.elements['value_text'] = self.canvas.create_text(
            self.x + self.width // 2, self.y + 10,
            text="0.0%",
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size + 2, "bold")
        )
        
        # Title
        self.elements['title'] = self.canvas.create_text(
            self.x + 10, self.y + self.height - 10,
            text=self.title,
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size),
            anchor="w"
        )
    
    def create_semicircular_gauge(self):
        """Create semicircular gauge"""
        center_x = self.x + self.width // 2
        center_y = self.y + self.height - 20
        radius = min(self.width, self.height) // 2 - 20
        
        # Background semicircle
        self.elements['background'] = self.canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=0, extent=180,
            fill=self.style.background_color,
            outline=self.style.border_color,
            width=2
        )
        
        # Gauge arc (will be updated)
        self.elements['gauge_arc'] = self.canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=180, extent=0,
            fill="", outline=self.style.primary_color,
            width=8, style=tk.ARC
        )
        
        # Value text
        self.elements['value_text'] = self.canvas.create_text(
            center_x, center_y - radius // 2,
            text="0.0%",
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size + 4, "bold")
        )
        
        # Title
        self.elements['title'] = self.canvas.create_text(
            center_x, center_y + 15,
            text=self.title,
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size)
        )
    
    def create_digital_gauge(self):
        """Create digital gauge"""
        # Background
        self.elements['background'] = self.canvas.create_rectangle(
            self.x + 5, self.y + 5,
            self.x + self.width - 5, self.y + self.height - 5,
            fill=self.style.background_color,
            outline=self.style.border_color,
            width=2
        )
        
        # Digital display
        self.elements['digital_display'] = self.canvas.create_text(
            self.x + self.width // 2, self.y + self.height // 2,
            text="00.0%",
            fill=self.style.primary_color,
            font=("Courier", self.style.font_size + 8, "bold")
        )
        
        # Title
        self.elements['title'] = self.canvas.create_text(
            self.x + 10, self.y + 10,
            text=self.title,
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size),
            anchor="w"
        )
        
        # Status indicator
        self.elements['status'] = self.canvas.create_oval(
            self.x + self.width - 20, self.y + 10,
            self.x + self.width - 10, self.y + 20,
            fill=self.style.primary_color,
            outline=""
        )
    
    def create_meter_gauge(self):
        """Create meter gauge"""
        # Background
        self.elements['background'] = self.canvas.create_rectangle(
            self.x + 5, self.y + 5,
            self.x + self.width - 5, self.y + self.height - 5,
            fill=self.style.background_color,
            outline=self.style.border_color,
            width=2
        )
        
        # Scale marks
        for i in range(11):
            x = self.x + 10 + (self.width - 20) * i / 10
            self.canvas.create_line(
                x, self.y + self.height - 15,
                x, self.y + self.height - 5,
                fill=self.style.text_color,
                width=1
            )
        
        # Meter needle (will be updated)
        needle_x = self.x + 10
        self.elements['needle'] = self.canvas.create_line(
            needle_x, self.y + self.height - 15,
            needle_x, self.y + 15,
            fill=self.style.primary_color,
            width=3
        )
        
        # Title
        self.elements['title'] = self.canvas.create_text(
            self.x + self.width // 2, self.y + 10,
            text=self.title,
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size)
        )
        
        # Value text
        self.elements['value_text'] = self.canvas.create_text(
            self.x + self.width // 2, self.y + self.height // 2,
            text="0.0%",
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size + 2)
        )
    
    def create_progress_gauge(self):
        """Create progress gauge"""
        # Background
        self.elements['background'] = self.canvas.create_rectangle(
            self.x + 5, self.y + 5,
            self.x + self.width - 5, self.y + self.height - 5,
            fill=self.style.background_color,
            outline=self.style.border_color,
            width=2
        )
        
        # Progress bar (will be updated)
        self.elements['progress'] = self.canvas.create_rectangle(
            self.x + 5, self.y + 5,
            self.x + 5, self.y + self.height - 5,
            fill=self.style.primary_color,
            outline=""
        )
        
        # Percentage text
        self.elements['percentage'] = self.canvas.create_text(
            self.x + self.width // 2, self.y + self.height // 2,
            text="0%",
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size + 2, "bold")
        )
        
        # Title
        self.elements['title'] = self.canvas.create_text(
            self.x + 10, self.y + 10,
            text=self.title,
            fill=self.style.text_color,
            font=(self.style.font_family, self.style.font_size),
            anchor="w"
        )
    
    def update_value(self, value: float, color: str = None, trend: str = "stable", 
                    predicted: float = None, velocity: float = 0.0):
        """Update gauge value with animation"""
        self.target_value = max(0, min(100, value))
        
        if color:
            self.colors['primary'] = color
        
        self.trend_label = trend
        self.predicted_value = predicted or value
        self.velocity = velocity
        
        # Add to history
        self.history.append(value)
        if len(self.history) > 50:
            self.history.pop(0)
        
        # Start animation
        if not self.is_animating:
            self.start_animation()
    
    def start_animation(self):
        """Start smooth animation"""
        if self.animation_thread and self.animation_thread.is_alive():
            return
        
        self.is_animating = True
        self.animation_thread = threading.Thread(target=self._animate, daemon=True)
        self.animation_thread.start()
    
    def _animate(self):
        """Animation loop"""
        while self.is_animating:
            try:
                # Calculate animation step
                diff = self.target_value - self.current_value
                
                if abs(diff) < 0.1:
                    self.current_value = self.target_value
                    self.is_animating = False
                    break
                
                # Apply animation based on type
                if self.style.animation_type == AnimationType.SMOOTH:
                    step = diff * self.style.animation_speed
                elif self.style.animation_type == AnimationType.BOUNCE:
                    step = diff * self.style.animation_speed * 1.5
                    if abs(step) < 1:
                        step = 1 if diff > 0 else -1
                elif self.style.animation_type == AnimationType.ELASTIC:
                    step = diff * self.style.animation_speed * 2
                    step *= math.sin(self.animation_progress * math.pi)
                elif self.style.animation_type == AnimationType.PULSE:
                    step = diff * self.style.animation_speed
                    # Add pulse effect
                    pulse = math.sin(self.animation_progress * 4) * 0.1
                    step += pulse
                else:  # GLOW
                    step = diff * self.style.animation_speed
                
                self.current_value += step
                self.animation_progress += 0.1
                
                # Update visual
                self.update_visual()
                
                # Control animation speed
                time.sleep(0.05)
                
            except Exception as e:
                print(f"Animation error: {e}")
                break
        
        self.animation_progress = 0.0
    
    def update_visual(self):
        """Update visual representation"""
        try:
            if self.gauge_type == GaugeType.CIRCULAR:
                self.update_circular_visual()
            elif self.gauge_type == GaugeType.LINEAR:
                self.update_linear_visual()
            elif self.gauge_type == GaugeType.SEMICIRCULAR:
                self.update_semicircular_visual()
            elif self.gauge_type == GaugeType.DIGITAL:
                self.update_digital_visual()
            elif self.gauge_type == GaugeType.METER:
                self.update_meter_visual()
            elif self.gauge_type == GaugeType.PROGRESS:
                self.update_progress_visual()
        except Exception as e:
            print(f"Visual update error: {e}")
    
    def update_circular_visual(self):
        """Update circular gauge visual"""
        center_x = self.x + self.width // 2
        center_y = self.y + self.height // 2
        radius = min(self.width, self.height) // 2 - 20
        
        # Update gauge arc
        extent = -360 * (self.current_value / 100)
        self.canvas.itemconfig(self.elements['gauge_arc'], extent=extent)
        
        # Update color
        color = self.colors.get('primary', self.style.primary_color)
        self.canvas.itemconfig(self.elements['gauge_arc'], outline=color)
        
        # Update value text
        self.canvas.itemconfig(self.elements['value_text'], text=f"{self.current_value:.1f}%")
        
        # Update trend
        if 'trend' in self.elements:
            trend_symbol = self.get_trend_symbol(self.trend_label)
            self.canvas.itemconfig(self.elements['trend'], text=trend_symbol)
        
        # Update prediction
        if 'prediction' in self.elements and self.style.show_predictions:
            pred_text = f"→{self.predicted_value:.1f}%"
            self.canvas.itemconfig(self.elements['prediction'], text=pred_text)
        
        # Add glow effect
        if self.style.glow_enabled and self.current_value > 75:
            self.add_glow_effect(center_x, center_y, radius, color)
    
    def update_linear_visual(self):
        """Update linear gauge visual"""
        # Update progress bar
        progress_width = (self.width - 20) * (self.current_value / 100)
        self.canvas.coords(
            self.elements['progress'],
            self.x + 10, self.y + self.height // 2 - 10,
            self.x + 10 + progress_width, self.y + self.height // 2 + 10
        )
        
        # Update color
        color = self.colors.get('primary', self.style.primary_color)
        self.canvas.itemconfig(self.elements['progress'], fill=color)
        
        # Update value text
        self.canvas.itemconfig(self.elements['value_text'], text=f"{self.current_value:.1f}%")
    
    def update_semicircular_visual(self):
        """Update semicircular gauge visual"""
        center_x = self.x + self.width // 2
        center_y = self.y + self.height - 20
        radius = min(self.width, self.height) // 2 - 20
        
        # Update gauge arc
        extent = 180 * (self.current_value / 100)
        self.canvas.itemconfig(self.elements['gauge_arc'], extent=extent)
        
        # Update color
        color = self.colors.get('primary', self.style.primary_color)
        self.canvas.itemconfig(self.elements['gauge_arc'], outline=color)
        
        # Update value text
        self.canvas.itemconfig(self.elements['value_text'], text=f"{self.current_value:.1f}%")
    
    def update_digital_visual(self):
        """Update digital gauge visual"""
        # Update digital display
        self.canvas.itemconfig(self.elements['digital_display'], 
                              text=f"{self.current_value:05.1f}%")
        
        # Update color
        color = self.colors.get('primary', self.style.primary_color)
        self.canvas.itemconfig(self.elements['digital_display'], fill=color)
        
        # Update status indicator
        if self.current_value > 75:
            status_color = "#ff0000"
        elif self.current_value > 50:
            status_color = "#ffff00"
        else:
            status_color = "#00ff00"
        
        self.canvas.itemconfig(self.elements['status'], fill=status_color)
    
    def update_meter_visual(self):
        """Update meter gauge visual"""
        # Update needle position
        needle_x = self.x + 10 + (self.width - 20) * (self.current_value / 100)
        self.canvas.coords(
            self.elements['needle'],
            needle_x, self.y + self.height - 15,
            needle_x, self.y + 15
        )
        
        # Update color
        color = self.colors.get('primary', self.style.primary_color)
        self.canvas.itemconfig(self.elements['needle'], fill=color)
        
        # Update value text
        self.canvas.itemconfig(self.elements['value_text'], text=f"{self.current_value:.1f}%")
    
    def update_progress_visual(self):
        """Update progress gauge visual"""
        # Update progress bar
        progress_width = (self.width - 10) * (self.current_value / 100)
        self.canvas.coords(
            self.elements['progress'],
            self.x + 5, self.y + 5,
            self.x + 5 + progress_width, self.y + self.height - 5
        )
        
        # Update color
        color = self.colors.get('primary', self.style.primary_color)
        self.canvas.itemconfig(self.elements['progress'], fill=color)
        
        # Update percentage text
        self.canvas.itemconfig(self.elements['percentage'], text=f"{int(self.current_value)}%")
    
    def add_glow_effect(self, center_x: int, center_y: int, radius: int, color: str):
        """Add glow effect to gauge"""
        # Create glow circles
        for i in range(3):
            glow_radius = radius + (i + 1) * 5
            alpha = 0.3 - (i * 0.1)
            glow_color = self.adjust_color_alpha(color, alpha)
            
            try:
                glow = self.canvas.create_oval(
                    center_x - glow_radius, center_y - glow_radius,
                    center_x + glow_radius, center_y + glow_radius,
                    fill="", outline=glow_color, width=2
                )
                self.canvas.tag_lower(glow)
            except Exception:
                pass
    
    def adjust_color_alpha(self, color: str, alpha: float) -> str:
        """Adjust color alpha for glow effect"""
        # Convert hex to RGB
        color = color.lstrip('#')
        r, g, b = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
        
        # Apply alpha (simplified)
        r = int(r * alpha)
        g = int(g * alpha)
        b = int(b * alpha)
        
        return f"#{r:02x}{g:02x}{b:02x}"
    
    def get_trend_symbol(self, trend: str) -> str:
        """Get trend symbol"""
        symbols = {
            "increasing": "↑",
            "decreasing": "↓",
            "stable": "→"
        }
        return symbols.get(trend, "→")
    
    def destroy(self):
        """Clean up gauge resources"""
        self.is_animating = False
        if self.animation_thread:
            self.animation_thread.join(timeout=1)
        
        # Delete canvas items
        for element_id in self.elements.values():
            try:
                self.canvas.delete(element_id)
            except Exception:
                pass

class AdvancedGaugeSystem:
    """Advanced gauge system with multiple responsive gauges"""
    
    def __init__(self, root: tk.Tk, hardware_monitor: AdvancedHardwareMonitor):
        self.root = root
        self.hardware_monitor = hardware_monitor
        self.gauges = {}
        self.is_running = False
        
        # Setup UI
        self.setup_ui()
        
        # Register callback
        self.hardware_monitor.add_callback(self.on_metrics_update)
    
    def setup_ui(self):
        """Setup the gauge system UI"""
        self.root.title("Advanced Hardware Performance Monitor")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0a0a0a")
        
        # Main frame
        main_frame = tk.Frame(self.root, bg="#0a0a0a")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="[MONITOR] Advanced Hardware Performance Monitor",
            bg="#0a0a0a", fg="#00ff00",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # Create gauge canvas
        self.canvas = Canvas(
            main_frame,
            bg="#1a1a1a",
            highlightthickness=0
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        # Create gauges
        self.create_gauges()
        
        # Control panel
        self.create_control_panel(main_frame)
    
    def create_gauges(self):
        """Create all gauges"""
        gauge_style = GaugeStyle(
            primary_color="#00ff00",
            secondary_color="#ff0000",
            background_color="#2a2a2a",
            text_color="#ffffff",
            border_color="#444444",
            glow_color="#00ff00",
            font_family="Arial",
            font_size=10,
            show_labels=True,
            show_values=True,
            show_trends=True,
            show_predictions=True,
            animation_type=AnimationType.SMOOTH,
            animation_speed=0.15,
            glow_enabled=True,
            gradient_enabled=True
        )
        
        # CPU Gauge (Circular)
        self.gauges['cpu'] = AdvancedGauge(
            self.canvas, 50, 50, 200, 200,
            GaugeType.CIRCULAR, gauge_style, "CPU Usage"
        )
        
        # Memory Gauge (Circular)
        self.gauges['memory'] = AdvancedGauge(
            self.canvas, 300, 50, 200, 200,
            GaugeType.CIRCULAR, gauge_style, "Memory Usage"
        )
        
        # Disk Gauge (Semicircular)
        self.gauges['disk'] = AdvancedGauge(
            self.canvas, 550, 50, 250, 150,
            GaugeType.SEMICIRCULAR, gauge_style, "Disk Usage"
        )
        
        # GPU Gauge (Linear)
        self.gauges['gpu'] = AdvancedGauge(
            self.canvas, 50, 300, 300, 80,
            GaugeType.LINEAR, gauge_style, "GPU Usage"
        )
        
        # Temperature Gauge (Digital)
        self.gauges['temperature'] = AdvancedGauge(
            self.canvas, 400, 300, 200, 100,
            GaugeType.DIGITAL, gauge_style, "CPU Temp"
        )
        
        # Health Gauge (Progress)
        self.gauges['health'] = AdvancedGauge(
            self.canvas, 650, 300, 300, 100,
            GaugeType.PROGRESS, gauge_style, "System Health"
        )
        
        # Network Gauge (Meter)
        self.gauges['network'] = AdvancedGauge(
            self.canvas, 50, 450, 400, 100,
            GaugeType.METER, gauge_style, "Network Activity"
        )
        
        # Battery Gauge (Circular)
        self.gauges['battery'] = AdvancedGauge(
            self.canvas, 500, 450, 150, 150,
            GaugeType.CIRCULAR, gauge_style, "Battery"
        )
    
    def create_control_panel(self, parent):
        """Create control panel"""
        control_frame = tk.Frame(parent, bg="#0a0a0a")
        control_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Start/Stop button
        self.start_button = tk.Button(
            control_frame,
            text="🚀 Start Monitoring",
            command=self.toggle_monitoring,
            bg="#00ff00", fg="#000000",
            font=("Arial", 10, "bold"),
            padx=20, pady=5
        )
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # Export button
        export_button = tk.Button(
            control_frame,
            text="[STATS] Export Data",
            command=self.export_data,
            bg="#0088ff", fg="#ffffff",
            font=("Arial", 10),
            padx=20, pady=5
        )
        export_button.pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_label = tk.Label(
            control_frame,
            text="Status: Ready",
            bg="#0a0a0a", fg="#ffffff",
            font=("Arial", 10)
        )
        self.status_label.pack(side=tk.RIGHT, padx=5)
    
    def toggle_monitoring(self):
        """Toggle hardware monitoring"""
        if self.is_running:
            self.hardware_monitor.stop_monitoring()
            self.is_running = False
            self.start_button.config(text="🚀 Start Monitoring", bg="#00ff00")
            self.status_label.config(text="Status: Stopped")
        else:
            self.hardware_monitor.start_monitoring()
            self.is_running = True
            self.start_button.config(text="[STOP] Stop Monitoring", bg="#ff0000")
            self.status_label.config(text="Status: Monitoring")
    
    def on_metrics_update(self, metrics: HardwareMetrics):
        """Handle metrics update"""
        try:
            # Update CPU gauge
            cpu_data = self.hardware_monitor.get_responsive_gauge_data("cpu")
            if cpu_data:
                self.gauges['cpu'].update_value(
                    cpu_data['value'],
                    cpu_data['color'],
                    cpu_data['trend'],
                    cpu_data['predicted'],
                    cpu_data['velocity']
                )
            
            # Update Memory gauge
            memory_data = self.hardware_monitor.get_responsive_gauge_data("memory")
            if memory_data:
                self.gauges['memory'].update_value(
                    memory_data['value'],
                    memory_data['color'],
                    memory_data['trend'],
                    memory_data['predicted'],
                    memory_data['velocity']
                )
            
            # Update Disk gauge
            disk_data = self.hardware_monitor.get_responsive_gauge_data("disk")
            if disk_data:
                self.gauges['disk'].update_value(
                    disk_data['value'],
                    disk_data['color'],
                    disk_data['trend'],
                    disk_data['predicted'],
                    disk_data['velocity']
                )
            
            # Update GPU gauge
            gpu_data = self.hardware_monitor.get_responsive_gauge_data("gpu")
            if gpu_data:
                self.gauges['gpu'].update_value(
                    gpu_data['value'],
                    gpu_data['color'],
                    gpu_data['trend'],
                    gpu_data['predicted'],
                    gpu_data['velocity']
                )
            
            # Update Temperature gauge
            temp_data = self.hardware_monitor.get_responsive_gauge_data("temperature")
            if temp_data:
                self.gauges['temperature'].update_value(
                    temp_data['value'],
                    temp_data['color'],
                    temp_data['trend'],
                    temp_data['predicted'],
                    temp_data['velocity']
                )
            
            # Update Health gauge
            health_data = self.hardware_monitor.get_responsive_gauge_data("health")
            if health_data:
                self.gauges['health'].update_value(
                    health_data['value'],
                    health_data['color'],
                    health_data['trend'],
                    health_data['predicted'],
                    health_data['velocity']
                )
            
            # Update Network gauge (combined sent/received)
            network_activity = (metrics.network_sent_mb_s + metrics.network_recv_mb_s) * 10  # Scale to 0-100
            network_color = self.get_gauge_color(network_activity, 50, "network")
            self.gauges['network'].update_value(
                network_activity,
                network_color,
                "stable"
            )
            
            # Update Battery gauge
            if metrics.battery_percent > 0:
                battery_color = self.get_gauge_color(100 - metrics.battery_percent, 20, "battery")
                self.gauges['battery'].update_value(
                    metrics.battery_percent,
                    battery_color,
                    "stable"
                )
            
        except Exception as e:
            print(f"Error updating gauges: {e}")
    
    def get_gauge_color(self, value: float, threshold: float, metric_type: str) -> str:
        """Get gauge color based on value and threshold"""
        if metric_type == "health":
            # Health score: higher is better
            if value >= 80:
                return "#00ff00"  # Green
            elif value >= 60:
                return "#ffff00"  # Yellow
            elif value >= 40:
                return "#ff8800"  # Orange
            else:
                return "#ff0000"  # Red
        elif metric_type == "battery":
            # Battery: higher is better
            if value >= 60:
                return "#00ff00"  # Green
            elif value >= 30:
                return "#ffff00"  # Yellow
            else:
                return "#ff0000"  # Red
        else:
            # Usage metrics: lower is better
            if value < threshold * 0.5:
                return "#00ff00"  # Green
            elif value < threshold * 0.75:
                return "#ffff00"  # Yellow
            elif value < threshold:
                return "#ff8800"  # Orange
            else:
                return "#ff0000"  # Red
    
    def export_data(self):
        """Export monitoring data"""
        try:
            self.hardware_monitor.export_metrics("hardware_performance_export.json")
            self.status_label.config(text="Status: Data exported")
        except Exception as e:
            self.status_label.config(text=f"Status: Export failed - {e}")
    
    def run(self):
        """Run the gauge system"""
        self.root.mainloop()

def main():
    """Main function"""
    import logging
    logging.info("[GAUGE] Advanced Gauge System starting")
    print("=" * 50)
    print("Responsive gauges with real-time hardware monitoring")
    print("[ART] Animated gauges with smooth transitions")
    print("[STATS] Real-time performance data visualization")
    print("[FIRE] Advanced monitoring with predictive analysis")
    print("=" * 50)
    
    # Create hardware monitor
    config = GaugeConfiguration(
        update_interval=0.5,
        history_size=100,
        smoothing_factor=0.3,
        alert_threshold_cpu=80.0,
        alert_threshold_memory=85.0,
        alert_threshold_disk=90.0,
        alert_threshold_temp=75.0,
        enable_gpu_monitoring=True,
        enable_network_monitoring=True,
        enable_battery_monitoring=True,
        enable_advanced_metrics=True,
        enable_predictive_alerts=True
    )
    
    hardware_monitor = AdvancedHardwareMonitor(config)
    
    # Create gauge system
    root = tk.Tk()
    gauge_system = AdvancedGaugeSystem(root, hardware_monitor)
    
    try:
        print("\n[MONITOR] Starting advanced gauge system...")
        gauge_system.run()
        
    except KeyboardInterrupt:
        print("\n[STOP] Monitoring stopped by user")
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        hardware_monitor.stop_monitoring()
        print("\n[FLAG] Advanced gauge system stopped")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
