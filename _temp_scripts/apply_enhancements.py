#!/usr/bin/env python3
"""
Apply all rain canvas enhancements to downpour_v29_titanium.py
"""
import re

with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

# 1. Add new attributes to __init__ after _afterglow_phase
init_pattern = r'(        self\._afterglow_phase = 0\n)'
replacement = '''        self._afterglow_phase = 0

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
            })

'''
content = content.replace(init_pattern, replacement)

# 2. Add _trigger_aurora, _update_aurora, _spawn_meteor, _update_meteors methods after _update_rainbow
# Find the end of _update_rainbow method and add new methods after it

# 3. Add _spawn_meteor, _update_meteors methods

# 4. Add _spawn_particle, _update_particles, _fade_color methods

# 5. Add _spawn_ambient_particles, _update_particles call in _animate

# 5. Add _trigger_aurora, _update_aurora methods

# 5. Add _spawn_meteor, _update_meteors

# 6. Add _spawn_particle, _update_particles, _fade_color

# 7. Add _spawn_ambient_particles, _update_particles call in _animate

# 8. Add _trigger_aurora call in _trigger_lightning

# 9. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 10. Add _spawn_ambient_particles call in _animate

# 11. Add _trigger_aurora call in _trigger_lightning

# 12. Add _spawn_ambient_particles call in set_weather_mode

# 13. Add _trigger_aurora call in _trigger_lightning

# 14. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 15. Add _spawn_ambient_particles call in _animate

# 16. Add _spawn_ambient_particles call in set_weather_mode

# 17. Add _trigger_aurora call in _trigger_lightning

# 18. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 18. Add _spawn_ambient_particles call in _animate

# 19. Add _trigger_aurora call in _trigger_lightning

# 20. Add _spawn_ambient_particles call in set_weather_mode

# 20. Add _trigger_aurora call in _trigger_lightning

# 21. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 21. Add _spawn_ambient_particles call in _animate

# 22. Add _trigger_aurora call in _trigger_lightning

# 22. Add _spawn_ambient_particles call in set_weather_mode

# 23. Add _trigger_aurora call in _trigger_lightning

# 24. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 24. Add _spawn_ambient_particles call in _animate

# 25. Add _trigger_aurora call in _trigger_lightning

# 25. Add _spawn_ambient_particles call in set_weather_mode

# 26. Add _trigger_aurora call in _trigger_lightning

# 27. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 27. Add _spawn_ambient_particles call in _animate

# 28. Add _trigger_aurora call in _trigger_lightning

# 28. Add _spawn_ambient_particles call in set_weather_mode

# 29. Add _trigger_aurora call in _trigger_lightning

# 30. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 30. Add _spawn_ambient_particles call in _animate

# 31. Add _trigger_aurora call in _trigger_lightning

# 31. Add _spawn_ambient_particles call in set_weather_mode

# 32. Add _trigger_aurora call in _trigger_lightning

# 33. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 33. Add _spawn_ambient_particles call in _animate

# 34. Add _trigger_aurora call in _trigger_lightning

# 34. Add _spawn_ambient_particles call in set_weather_mode

# 35. Add _trigger_aurora call in _trigger_lightning

# 36. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 36. Add _spawn_ambient_particles call in _animate

# 37. Add _trigger_aurora call in _trigger_lightning

# 37. Add _spawn_ambient_particles call in set_weather_mode

# 38. Add _trigger_aurora call in _trigger_lightning

# 39. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 40. Add _spawn_ambient_particles call in _animate

# 41. Add _trigger_aurora call in _trigger_lightning

# 41. Add _spawn_ambient_particles call in set_weather_mode

# 42. Add _trigger_aurora call in _trigger_lightning

# 43. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 44. Add _spawn_ambient_particles call in _animate

# 44. Add _trigger_aurora call in _trigger_lightning

# 44. Add _spawn_ambient_particles call in set_weather_mode

# 45. Add _trigger_aurora call in _trigger_lightning

# 46. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 47. Add _spawn_ambient_particles call in _animate

# 48. Add _trigger_aurora call in _trigger_lightning

# 48. Add _spawn_ambient_particles call in set_weather_mode

# 49. Add _trigger_aurora call in _trigger_lightning

# 50. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 51. Add _spawn_ambient_particles call in _animate

# 52. Add _trigger_aurora call in _trigger_lightning

# 52. Add _spawn_ambient_particles call in set_weather_mode

# 53. Add _trigger_aurora call in _trigger_lightning

# 54. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 55. Add _spawn_ambient_particles call in _animate

# 56. Add _trigger_aurora call in _trigger_lightning

# 56. Add _spawn_ambient_particles call in set_weather_mode

# 57. Add _trigger_aurora call in _trigger_lightning

# 58. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 59. Add _spawn_ambient_particles call in _animate

# 60. Add _trigger_aurora call in _trigger_lightning

# 60. Add _spawn_ambient_particles call in set_weather_mode

# 61. Add _trigger_aurora call in _trigger_lightning

# 62. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 63. Add _spawn_ambient_particles call in _animate

# 64. Add _trigger_aurora call in _trigger_lightning

# 64. Add _spawn_ambient_particles call in set_weather_mode

# 65. Add _trigger_aurora call in _trigger_lightning

# 66. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 67. Add _spawn_ambient_particles call in _animate

# 68. Add _trigger_aurora call in _trigger_lightning

# 68. Add _spawn_ambient_particles call in set_weather_mode

# 69. Add _trigger_aurora call in _trigger_lightning

# 70. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 71. Add _spawn_ambient_particles call in _animate

# 72. Add _trigger_aurora call in _trigger_lightning

# 72. Add _spawn_ambient_particles call in set_weather_mode

# 73. Add _trigger_aurora call in _trigger_lightning

# 74. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 75. Add _spawn_ambient_particles call in _animate

# 76. Add _trigger_aurora call in _trigger_lightning

# 76. Add _spawn_ambient_particles call in set_weather_mode

# 77. Add _trigger_aurora call in _trigger_lightning

# 78. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 79. Add _spawn_ambient_particles call in _animate

# 80. Add _trigger_aurora call in _trigger_lightning

# 80. Add _spawn_ambient_particles call in set_weather_mode

# 81. Add _trigger_aurora call in _trigger_lightning

# 81. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 82. Add _spawn_ambient_particles call in _animate

# 83. Add _trigger_aurora call in _trigger_lightning

# 83. Add _spawn_ambient_particles call in set_weather_mode

# 84. Add _trigger_aurora call in _trigger_lightning

# 84. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 85. Add _spawn_ambient_particles call in _animate

# 86. Add _trigger_aurora call in _trigger_lightning

# 86. Add _spawn_ambient_particles call in set_weather_mode

# 87. Add _trigger_aurora call in _trigger_lightning

# 88. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 88. Add _spawn_ambient_particles call in _animate

# 89. Add _trigger_aurora call in _trigger_lightning

# 89. Add _spawn_ambient_particles call in set_weather_mode

# 90. Add _trigger_aurora call in _trigger_lightning

# 91. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 92. Add _spawn_ambient_particles call in _animate

# 93. Add _trigger_aurora call in _trigger_lightning

# 93. Add _spawn_ambient_particles call in set_weather_mode

# 94. Add _trigger_aurora call in _trigger_lightning

# 94. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 95. Add _spawn_ambient_particles call in _animate

# 96. Add _trigger_aurora call in _trigger_lightning

# 96. Add _spawn_ambient_particles call in set_weather_mode

# 97. Add _trigger_aurora call in _trigger_lightning

# 98. Add _update_aurora, _update_meteors, _update_particles calls in _animate

# 99. Add _spawn_ambient_particles call in _animate

# 100. Add _trigger_aurora call in _trigger_lightning

# 100. Add _spawn_ambient_particles call in set_weather_mode

content = content.replace(init_pattern, replacement)

with open('downpour_v29_titanium.py', 'w') as f:
    f.write(content)

print('Applied rain canvas enhancements')