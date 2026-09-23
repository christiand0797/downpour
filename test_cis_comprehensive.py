import sys
sys.path.insert(0, '.')

from cognitive_immune_system import create_cognitive_immune_system, Epitope

cis = create_cognitive_immune_system({'naive_pool_size': 100, 'max_detectors': 1000})

# Test 1: Antigen presentation
epitope = Epitope(pattern='test_process_injection', pattern_type='behavior', affinity=0.9)
cis._present_antigen(epitope, {'source': 'test', 'technique': 'T1055'})

# Test 2: Clonal expansion and evolution
cis._clonal_selection()
cis._somatic_hypermutation()

# Test 3: Red teamer simulation
red_teamer = cis.red_teamer
red_teamer._run_attack_simulation()

# Test 4: Threat evolution prediction
predictor = cis.predictor
predictor._generate_predictions()

# Test 5: Semantic integrity verifier
verifier = cis.verifier
verifier._capture_baselines()

# Test 5: Get immune status
status = cis.get_immune_status()
print('Total detectors:', status['total_detectors'])
print('Memory epitopes:', status['memory_epitopes'])
print('Active responses:', status['active_responses'])
print('Signal queue size:', status['signal_queue_size'])
print('Stats:', status['stats'])
print('All CIS components working!')
cis.stop()
print('All tests passed!')