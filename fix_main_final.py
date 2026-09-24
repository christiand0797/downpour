with open('cognitive_immune_system.py', 'r') as f:
    lines = f.readlines()

# Find the if __main__ line
for i, line in enumerate(lines):
    if 'if __name__ == "__main__":' in line:
        print(f'Found at line {i+1}')
        # Insert test code after this line
        test_code = [
            '\n',
            '    # Quick test\n',
            '    logging.basicConfig(level=logging.INFO)\n',
            '\n',
            '    cis = create_cognitive_immune_system({\n',
            '        "naive_pool_size": 100,\n',
            '        "max_detectors": 1000,\n',
            '        "affinity_threshold": 0.7,\n',
            '        "clonal_expansion_factor": 3,\n',
            '        "mutation_rate": 0.1\n',
            '    })\n',
            '\n',
            '    print("=== Cognitive Immune System Test ===")\n',
            '    print(f"Initial detectors: {len(cis.detectors)}")\n',
            '\n',
            '    # Test antigen presentation\n',
            '    test_epitope = Epitope(pattern="malicious_process_injection", pattern_type="behavior", affinity=0.9)\n',
            '    cis._present_antigen(test_epitope, {"source": "test", "technique": "T1055"})\n',
            '\n',
            '    print(f"After presentation: {len(cis.detectors)} detectors")\n',
            '\n',
            '    status = cis.get_immune_status()\n',
            '    print(f"Status: {json.dumps(status, indent=2, default=str)}")\n',
            '\n',
            '    # Test evolution\n',
            '    cis._clonal_selection()\n',
            '    cis._somatic_hypermutation()\n',
            '    print(f"After evolution: {len(cis.detectors)} detectors")\n',
            '\n',
            '    # Test threat hunting\n',
            '    print("=== Threat Hunting Test ===")\n',
            '    hunter = cis.threat_hunter if hasattr(cis, \'threat_hunter\') else None\n',
            '    if hunter:\n',
            '        hunter.start()\n',
            '        time.sleep(1)\n',
            '        hunter.stop()\n',
            '\n',
            '    print("=== Test Complete ===")\n'
        ]
        
        # Insert the test code after the if __main__ line
        new_lines = lines[:i+1] + test_code + ['\n'] + lines[i+1:]
        
        with open('cognitive_immune_system.py', 'w') as f:
            f.writelines(new_lines)
        
        print("Test code added successfully")