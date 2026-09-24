import re

with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

cis_tab_method = '''

    # ==========================================================================
    #  COGNITIVE IMMUNE SYSTEM (CIS) TAB
    # ==========================================================================

    def _build_cis_tab(self):
        p: Any = self._tab_cis
        tk.Label(p, text="COGNITIVE IMMUNE SYSTEM (CIS)", font=('Consolas', 12, 'bold'),
                 fg = Colors.GAUGE_TEAL, bg=Colors.BG_VOID).pack(anchor='w', padx=10, pady=10)

        # -- Status overview ---
        status_frame: Any = tk.Frame(p, bg=Colors.GLASS_CARD)
        status_frame.pack(fill='x', padx=10, pady=4)
        tk.Label(status_frame, text="CIS Status", font=('Consolas', 10, 'bold'),
                 fg = Colors.GAUGE_ORANGE, bg=Colors.GLASS_CARD).pack(anchor='w', padx=8, pady=4)

        self._cis_status_var = tk.StringVar(value="Initializing...")
        tk.Label(p, textvariable=self._cis_status_var, font=('Consolas', 9),
                 fg = Colors.GAUGE_TEAL, bg=Colors.BG_VOID).pack(anchor='w', padx=10, pady=2)

        # -- Detector stats ---
        stats_frame: Any = tk.Frame(p, bg=Colors.GLASS_CARD)
        stats_frame.pack(fill='x', padx=10, pady=4)
        tk.Label(stats_frame, text="Detector Statistics", font=('Consolas', 10, 'bold'),
                 fg = Colors.GAUGE_ORANGE, bg=Colors.GLASS_CARD).pack(anchor='w', padx=8, pady=4)

        self._cis_stats_vars = {}
        for label, key in [
            ('Total Detectors:', 'total_detectors'),
            ('Memory Epitopes:', 'memory_epitopes'),
            ('Active Responses:', 'active_responses'),
            ('Signal Queue:', 'signal_queue_size'),
            ('Clonal Expansions:', 'clonal_expansions'),
            ('Somatic Mutations:', 'somatic_mutations'),
            ('Detectors Created:', 'detectors_created'),
            ('Detectors Retired:', 'detectors_retired'),
            ('Threats Contained:', 'threats_contained'),
            ('Autoimmune Events:', 'autoimmune_events'),
        ]:
            row: Any = tk.Frame(stats_frame, bg=Colors.GLASS_CARD)
            row.pack(fill='x', padx=8, pady=1)
            tk.Label(row, text=label, font=('Consolas', 9), fg=Colors.TEXT_DIM,
                     bg = Colors.GLASS_CARD).pack(side='left')
            var: Any = tk.StringVar(value='0')
            tk.Label(row, textvariable=var, font=('Consolas', 9, 'bold'),
                     fg = Colors.GAUGE_TEAL, bg=Colors.GLASS_CARD).pack(side='right')
            self._cis_stats_vars[key] = var

        # -- Red Teamer status ---
        rt_frame: Any = tk.Frame(p, bg=Colors.GLASS_CARD)
        rt_frame.pack(fill='x', padx=10, pady=4)
        tk.Label(rt_frame, text="Adversarial Red Teamer", font=('Consolas', 10, 'bold'),
                 fg = Colors.GAUGE_PURPLE, bg=Colors.GLASS_CARD).pack(anchor='w', padx=8, pady=4)

        rt_row: Any = tk.Frame(rt_frame, bg=Colors.GLASS_CARD)
        rt_row.pack(fill='x', padx=8, pady=2)
        tk.Label(rt_row, text="Status:", font=('Consolas', 9), fg=Colors.TEXT_DIM,
                 bg = Colors.GLASS_CARD).pack(side='left')
        self._cis_rt_status = tk.StringVar(value="Stopped")
        tk.Label(rt_row, textvariable=self._cis_rt_status, font=('Consolas', 9, 'bold'),
                 fg = Colors.GAUGE_PURPLE, bg=Colors.GLASS_CARD).pack(side='right', padx=4)

        rt_row2: Any = tk.Frame(rt_frame, bg=Colors.GLASS_CARD)
        rt_row2.pack(fill='x', padx=8, pady=2)
        tk.Label(rt_row2, text="Last Run:", font=('Consolas', 9), fg=Colors.TEXT_DIM,
                 bg = Colors.GLASS_CARD).pack(side='left')
        self._cis_rt_last = tk.StringVar(value="Never")
        tk.Label(rt_row2, textvariable=self._cis_rt_last, font=('Consolas', 9, 'bold'),
                 fg = Colors.GAUGE_PURPLE, bg=Colors.GLASS_CARD).pack(side='right', padx=4)

        rt_row3: Any = tk.Frame(rt_frame, bg=Colors.GLASS_CARD)
        rt_row3.pack(fill='x', padx=8, pady=2)
        tk.Label(rt_row3, text="Detections:", font=('Consolas', 9), fg=Colors.TEXT_DIM,
                 bg = Colors.GLASS_CARD).pack(side='left')
        self._cis_rt_detections = tk.StringVar(value="0")
        tk.Label(rt_row3, textvariable=self._cis_rt_detections, font=('Consolas', 9, 'bold'),
                 fg = Colors.GAUGE_PURPLE, bg=Colors.GLASS_CARD).pack(side='right', padx=4)

        # -- Threat Evolution Predictor ---
        te_frame: Any = tk.Frame(p, bg=Colors.GLASS_CARD)
        te_frame.pack(fill='x', padx=10, pady=4)
        tk.Label(te_frame, text="Threat Evolution Predictor", font=('Consolas', 10, 'bold'),
                 fg = Colors.GAUGE_ORANGE, bg=Colors.GLASS_CARD).pack(anchor='w', padx=8, pady=4)

        te_row: Any = tk.Frame(te_frame, bg=Colors.GLASS_CARD)
        te_row.pack(fill='x', padx=8, pady=2)
        tk.Label(te_row, text="Status:", font=('Consolas', 9), fg=Colors.TEXT_DIM,
                 bg = Colors.GLASS_CARD).pack(side='left')
        self._cis_te_status = tk.StringVar(value="Running")
        tk.Label(te_row, textvariable=self._cis_te_status, font=('Consolas', 9, 'bold'),
                 fg = Colors.GAUGE_ORANGE, bg=Colors.GLASS_CARD).pack(side='right', padx=4)

        # -- Semantic Integrity Verifier ---
        si_frame: Any = tk.Frame(p, bg=Colors.GLASS_CARD)
        si_frame.pack(fill='x', padx=10, pady=4)
        tk.Label(si_frame, text="Semantic Integrity Verifier", font=('Consolas', 10, 'bold'),
                 fg = Colors.GAUGE_RED, bg=Colors.GLASS_CARD).pack(anchor='w', padx=8, pady=4)

        si_row: Any = tk.Frame(si_frame, bg=Colors.GLASS_CARD)
        si_row.pack(fill='x', padx=8, pady=2)
        tk.Label(si_row, text="Status:", font=('Consolas', 9), fg=Colors.TEXT_DIM,
                 bg = Colors.GLASS_CARD).pack(side='left')
        self._cis_si_status = tk.StringVar(value="Monitoring")
        tk.Label(si_row, textvariable=self._cis_si_status, font=('Consolas', 9, 'bold'),
                 fg = Colors.GAUGE_RED, bg=Colors.GLASS_CARD).pack(side='right', padx=4)

        # -- Controls ---
        ctrl_frame: Any = tk.Frame(p, bg=Colors.GLASS_CARD)
        ctrl_frame.pack(fill='x', padx=10, pady=8)

        def _toggle_red_teamer():
            if hasattr(self, 'cis') and self.cis:
                if hasattr(self.cis, 'red_teamer') and self.cis.red_teamer:
                    if self.cis.red_teamer.running:
                        self.cis.red_teamer.stop()
                        self._cis_rt_status.set("Stopped")
                    else:
                        self.cis.red_teamer.start()
                        self._cis_rt_status.set("Running")

        def _toggle_predictor():
            if hasattr(self, 'cis') and self.cis:
                if hasattr(self.cis, 'predictor') and self.cis.predictor:
                    if self.cis.predictor.running:
                        self.cis.predictor.stop()
                        self._cis_te_status.set("Stopped")
                    else:
                        self.cis.predictor.start()
                        self._cis_te_status.set("Running")

        def _toggle_verifier():
            if hasattr(self, 'cis') and self.cis:
                if hasattr(self.cis, 'verifier') and self.cis.verifier:
                    if self.cis.verifier.running:
                        self.cis.verifier.stop()
                        self._cis_si_status.set("Stopped")
                    else:
                        self.cis.verifier.start()
                        self._cis_si_status.set("Monitoring")

        btn_row: Any = tk.Frame(ctrl_frame, bg=Colors.GLASS_CARD)
        btn_row.pack(fill='x', pady=4)
        tk.Button(btn_row, text="Toggle Red Teamer", font=('Consolas', 9, 'bold'),
                  fg = Colors.GAUGE_PURPLE, bg=Colors.GLASS_CARD,
                  activebackground = Colors.GLASS_LIGHT, activeforeground=Colors.GAUGE_PURPLE,
                  relief = 'flat', padx=8, pady=3, cursor='hand2',
                  command = _toggle_red_teamer).pack(side='left', padx=4)
        tk.Button(btn_row, text="Toggle Predictor", font=('Consolas', 9, 'bold'),
                  fg = Colors.GAUGE_ORANGE, bg=Colors.GLASS_CARD,
                  activebackground = Colors.GLASS_LIGHT, activeforeground=Colors.GAUGE_ORANGE,
                  relief = 'flat', padx=8, pady=3, cursor='hand2',
                  command = _toggle_predictor).pack(side='left', padx=4)
        tk.Button(btn_row, text="Toggle Verifier", font=('Consolas', 9, 'bold'),
                  fg = Colors.GAUGE_RED, bg=Colors.GLASS_CARD,
                  activebackground = Colors.GLASS_LIGHT, activeforeground=Colors.GAUGE_RED,
                  relief = 'flat', padx=8, pady=3, cursor='hand2',
                  command = _toggle_verifier).pack(side='left', padx=4)

        # -- Refresh button ---
        def _refresh_cis_stats():
            if hasattr(self, 'cis') and self.cis:
                status = self.cis.get_immune_status()
                self._cis_status_var.set(f"Running | Detectors: {status['total_detectors']} | Memory: {status['memory_epitopes']} | Responses: {status['active_responses']}")
                for key, var in self._cis_stats_vars.items():
                    var.set(str(status['stats'].get(key, 0)))
                if hasattr(self, 'cis') and self.cis.red_teamer:
                    rt = self.cis.red_teamer
                    self._cis_rt_status.set("Running" if rt.running else "Stopped")
                    self._cis_rt_last.set(rt.results_history[-1]['timestamp'].strftime('%H:%M:%S') if rt.results_history else "Never")
                    self._cis_rt_detections.set(str(len(rt.results_history)))

        tk.Button(ctrl_frame, text="Refresh Stats", font=('Consolas', 9, 'bold'),
                  fg = Colors.GAUGE_TEAL, bg=Colors.GLASS_CARD,
                  activebackground = Colors.GLASS_LIGHT, activeforeground=Colors.GAUGE_TEAL,
                  relief = 'flat', padx=8, pady=3, cursor='hand2',
                  command = _refresh_cis_stats).pack(side='right', padx=4)

        # Auto-refresh timer
        def _auto_refresh_cis():
            if hasattr(self, 'cis') and self.cis and self.winfo_exists():
                try:
                    _refresh_cis_stats()
                except Exception:
                    pass
                self.after(5000, _auto_refresh_cis)

        self.after(5000, _auto_refresh_cis)

"""

# Find the BELL section position
with open('downpour_v29_titanium.py', 'r') as f:
    content = f.read()

idx = content.find('# ==========================================================================\n    #  [BELL] SOUND ALARM ENGINE')
if idx >= 0:
    print(f'BELL section at: {idx}')
    # Insert before this
    new_content = content[:idx] + cis_tab_method + '\n' + content[idx:]
    with open('downpour_v29_titanium.py', 'w') as f:
        f.write(new_content)
    print('Inserted _build_cis_tab successfully')
else:
    print('BELL section not found')