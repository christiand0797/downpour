#!/usr/bin/env python3
"""
Add rain canvas enhancements to downpour_v29_titanium.py - precise insertion
"""
with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

# Find the exact location after "self._afterglow_phase = 0"
marker = "        self._afterglow_phase = 0\n"
idx = content.find(marker)
if idx == -1:
    print("Marker not found")
    exit(1)

# Insert after this line
insert_pos = idx + len(marker)

new_attrs = '''
        # v29.80: Weather mode support (rain, snow, sleet)
        self._weather_mode = 'rain'  # 'rain', 'snow', 'sleet'
        # v29.80: Thunder audio and screen shake
        self._thunder_enabled = True
        self._shake_enabled = True
        self._shake_phase = 0
        self._shake_timer = 0
        self._shake_intensity = 0
        self._shake_origin = None  # original window geometry for shake reset

        # v29.80: Rainbow effect initialization
        self._rainbow_phase = 0
        self._rainbow_intensity = 0
        self._rainbow_x = 0
        self._rainbow_y = 0
        self._rainbow_arc = None
        self._rainbow_arc2 = None
        self._rainbow_arc3 = None
        self._rainbow_arc4 = None
        self._rainbow_arc5 = None
        self._rainbow_arc6 = None

        # v29.80: Aurora borealis effect initialization
        self._aurora_phase = 0
        self._aurora_intensity = 0
        self._aurora_color_phase = 0.0
        self._aurora_speed = 0.0
        self._aurora_bands = []
        self._aurora_items = []

        # v29.80: Meteor shower initialization
        self._meteor_pool = 8
        self._meteor_items = []
        self._meteor_state = []
        for _ in range(self._meteor_pool):
            mid: Any = self.create_line(-20, -20, -10, -10, 
                                       fill='#ffff88', width=2, state='hidden')
            self._meteor_items.append(mid)
            self._meteor_state.append({
                'x': -100, 'y': -100,
                'vx': 0, 'vy': 0,
                'life': 0, 'max_life': 0,
                'width': 0,
                'glow': 0
            })

        # v29.80: Enhanced lightning forks
        self._lightning_forks = []
        self._lightning_fork_pool = 12

        # v29.80: Particle system for atmospheric effects
        self._particle_pool = 64
        self._particle_items = []
        self._particle_state = []
        for _ in range(self._particle_pool):
            pid: Any = self.create_oval(-10, -10, -5, -5,
                                       fill='#88ccee', outline='', state='hidden')
            self._particle_items.append(pid)
            self._particle_state.append({
                'x': -100, 'y': -100,
                'vx': 0, 'vy': 0,
                'life': 0, 'max_life': 0,
                'size': 1,
                'color': '#88ccee',
                'alpha': 1.0,
                'gravity': 0.0
            )
'''

# Insert after the marker
insert_pos = content.find(marker) + len(marker)
new_content = content[:insert_pos] + new_attrs + content[insert_pos:]

with open('downpour_v29_titanium.py', 'w') as f:
    f.write(new_content)

print('Inserted new attributes successfully')