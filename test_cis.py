import sys
sys.path.insert(0, '.')

from cognitive_immune_system import create_cognitive_immune_system, Epitope

cis = create_cognitive_immune_system({'naive_pool_size': 50})
print('CIS created successfully')
print('Detectors:', len(cis.detectors))

# Test antigen presentation
epitope = Epitope(pattern='test_malicious_behavior', pattern_type='behavior', affinity=0.9)
cis._present_antigen(epitope, {'source': 'test', 'technique': 'T1055'})
print('After presentation:', len(cis.detectors), 'detectors')

status = cis.get_immune_status()
print('Status:', status['total_detectors'], 'detectors,', status['memory_epitopes'], 'memory epitopes')
print('Test passed!')

cis.stop()