with open('cognitive_immune_system.py', 'r') as f:
    content = f.read()

# Find the if __main__ line
idx = content.find('if __name__ == "__main__":')
if idx >= 0:
    # Find the end of the file after the if __main__ line
    # We need to add the test code after the opening brace
    # Find the end of the if __main__ block (or end of file)
    
    # Find where the test code should end (should be near the end of file)
    # Let's just append the test code after the if __main__ line
    test_code = '''

    cis = create_cognitive_immune_system({
        "naive_pool_size": 100,
        "max_detectors": 1000,
        "affinity_threshold": 0.7,
        "clonal_expansion_factor": 3,
        "mutation_rate": 0.1
    })

    print("=== Cognitive Immune System Test ===")
    print(f"Initial detectors: {len(cis.detectors)}")

    # Test antigen presentation
    test_epitope = Epitope(pattern="malicious_process_injection", pattern_type="behavior", affinity=0.9)
    cis._present_antigen(test_epitope, {"source": "test", "technique": "T1055"})

    print(f"After presentation: {len(cis.detectors)} detectors")

    status = cis.get_immune_status()
    print(f"Status: {json.dumps(status, indent=2, default=str)}")

    # Test evolution
    cis._clonal_selection()
    cis._somatic_hypermutation()
    print(f"After evolution: {len(cis.detectors)} detectors")

    # Test threat hunting
    print("=== Threat Hunting Test ===")
    hunter = cis.threat_hunter if hasattr(cis, 'threat_hunter') else None
    if hunter:
        hunter.start()
        time.sleep(1)
        hunter.stop()

    print("=== Test Complete ===")'''

    # Find the end of the if __main__ block (look for the next function or end of file)
    # The if __main__ block should end before the next function or end of file
    # Find the next 'def ' after the if __main__ line
    next_def = content.find('\ndef ', idx)
    if next_def == -1:
        next_def = len(content)
    
    # Check if there's already test code in the if __main__ block
    main_block = content[idx:next_def]
    if 'Test Complete' not in main_block:
        # Insert the test code before the next function or end of file
        new_content = content[:next_def] + test_code + '\n\n' + content[next_def:]
        with open('cognitive_immune_system.py', 'w') as f:
            f.write(new_content)
        print("Test code added successfully")
    else:
        print("Test code already present")
else:
    print("if __main__ not found")