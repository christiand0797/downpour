from cognitive_immune_system import (
    create_cognitive_immune_system, integrate_with_downpour,
    CognitiveImmuneSystem, AdversarialRedTeamer, ThreatEvolutionPredictor,
    SemanticIntegrityVerifier, Epitope, Signal, Detector, CellType, SignalType
)
print("All imports OK")

# Test instantiation
cis = create_cognitive_immune_system()
print("CIS created OK")
print("  neuromorphic:", cis.neuromorphic)
print("  deception:", cis.deception_technology)
print("  federated:", cis.federated_intel)
print("  self_healing:", cis.self_healing)
print("  red_teamer:", cis.red_teamer)
print("  threat_predictor:", cis.threat_predictor)
print("  integrity_verifier:", cis.integrity_verifier)

# Test start
cis.start()
print("CIS started OK")

import time
time.sleep(3)

cis.stop()
print("CIS stopped OK")
print("ALL TESTS PASSED")