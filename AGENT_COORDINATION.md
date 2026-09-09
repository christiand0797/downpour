# Downpour Agent Coordination Protocol

## Overview
This document defines how multiple AI agents can coordinate work on the Downpour codebase using shared state files.

## Coordination Files

### 1. WORK_QUEUE.json
Central task queue for all agents
```json
{
  "tasks": [
    {
      "id": "TASK-001",
      "title": "Optimize memory scanner performance",
      "status": "pending",
      "assignee": "unassigned",
      "priority": "high",
      "dependencies": [],
      "files": ["downpour_v29_titanium.py", "process_monitor.py"],
      "created": "2026-09-03T10:00:00Z",
      "claimed_at": null,
      "completed_at": null
    }
  ]
}
```

### 2. AGENT_REGISTRY.json
Active agents and their capabilities
```json
{
  "agents": [
    {
      "id": "agent-perf-001",
      "name": "Performance Optimizer",
      "specialization": ["performance", "memory", "cpu"],
      "status": "active",
      "current_task": "TASK-001",
      "heartbeat": "2026-09-03T10:05:00Z"
    }
  ]
}
```

### 3. SHARED_CONTEXT.md
Human-readable shared knowledge base updated by all agents

### 4. CHANGELOG_AGENTS.md
Agent-specific change log (supplements main CHANGELOG.md)

---

## Agent Workflow

### Starting Work
1. Read `WORK_QUEUE.json` for available tasks
2. Claim task by updating `assignee` and `status` to "in_progress"
3. Register in `AGENT_REGISTRY.json` with heartbeat
4. Create/update `SHARED_CONTEXT.md` with findings

### During Work
- Update task progress in `WORK_QUEUE.json` every 5-10 min
- Update heartbeat in `AGENT_REGISTRY.json` every 30 sec
- Log significant findings to `SHARED_CONTEXT.md`
- Write atomic changes to code files

### Completing Work
1. Update task status to "completed" with `completed_at` timestamp
2. Log changes to `CHANGELOG_AGENTS.md`
3. Update `SHARED_CONTEXT.md` with summary
4. Release task assignment
5. Update agent status to "idle"

---

## Communication Protocol

### Task Handoff
When passing work to another agent:
```json
{
  "from_agent": "agent-perf-001",
  "to_agent": "agent-security-002",
  "task_id": "TASK-001",
  "handoff_note": "Optimized memory scanner, needs security review of new caching logic",
  "files_modified": ["downpour_v29_titanium.py:22450-22600", "process_monitor.py:100-150"]
}
```

### Blocking Issues
```json
{
  "task_id": "TASK-001",
  "blocked_by": "Missing API in config.py",
  "blocking_agent": "agent-config-003",
  "resolution_needed": "Add get_adaptive_threshold() method"
}
```

---

## File Locking Convention

To prevent conflicts, agents use lightweight file locks:
- Create `.lock.<filename>` before editing
- Delete after commit
- Max lock time: 5 minutes
- Other agents wait or pick different task

---

## Specialized Agent Roles

| Agent ID Prefix | Specialization | Typical Tasks |
|-----------------|----------------|---------------|
| `agent-perf-*` | Performance, memory, CPU | Gauge optimization, thread pooling, caching |
| `agent-security-*` | Threat detection, hardening | YARA rules, behavioral analysis, remediation |
| `agent-ui-*` | GUI, tabs, dashboards | Tab reorganization, widget fixes, themes |
| `agent-net-*` | Network, VPN, DNS | Kill switch, port analysis, leak prevention |
| `agent-config-*` | Configuration, settings | Hardware profiles, adaptive tuning |
| `agent-test-*` | Testing, validation | Thread safety, integration tests |

---

## Example Session

```bash
# Agent 1 claims a task
python -c "
import json, datetime
with open('WORK_QUEUE.json') as f: q = json.load(f)
for t in q['tasks']:
    if t['id'] == 'TASK-001':
        t['assignee'] = 'agent-perf-001'
        t['status'] = 'in_progress'
        t['claimed_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
with open('WORK_QUEUE.json', 'w') as f: json.dump(q, f, indent=2)
"

# Agent 1 registers
python -c "
import json, datetime
with open('AGENT_REGISTRY.json') as f: r = json.load(f)
r['agents'].append({
    'id': 'agent-perf-001',
    'name': 'Performance Optimizer',
    'specialization': ['performance', 'memory'],
    'status': 'active',
    'current_task': 'TASK-001',
    'heartbeat': datetime.datetime.utcnow().isoformat() + 'Z'
})
with open('AGENT_REGISTRY.json', 'w') as f: json.dump(r, f, indent=2)
"
```

---

## Integration with Downpour Codebase

### Adding Coordination to Main App
In `downpour_v29_titanium.py`:
```python
def _agent_coordination_init(self):
    """Initialize agent coordination files on startup"""
    import json, os
    for fname, default in [
        ('WORK_QUEUE.json', {'tasks': []}),
        ('AGENT_REGISTRY.json', {'agents': []}),
    ]:
        if not os.path.exists(fname):
            with open(fname, 'w') as f:
                json.dump(default, f, indent=2)
```

### Heartbeat Monitor
```python
def _agent_heartbeat_monitor(self):
    """Clean up stale agents every 60s"""
    import json, time, datetime
    while self._tk_alive:
        time.sleep(60)
        try:
            with open('AGENT_REGISTRY.json') as f:
                reg = json.load(f)
            now = time.time()
            for agent in reg['agents']:
                hb = datetime.datetime.fromisoformat(agent['heartbeat'].replace('Z', '+00:00')).timestamp()
                if now - hb > 120:  # 2 min stale
                    agent['status'] = 'stale'
            with open('AGENT_REGISTRY.json', 'w') as f:
                json.dump(reg, f, indent=2)
        except Exception:
            pass
```

---

## Quick Commands for Agents

```bash
# View available tasks
cat WORK_QUEUE.json | python -m json.tool

# View active agents
cat AGENT_REGISTRY.json | python -m json.tool

# View shared context
cat SHARED_CONTEXT.md

# Claim task TASK-XXX
python -c "import json, datetime; ..."  # see workflow above

# Update progress
python -c "import json; ... update task progress ..."

# Complete task
python -c "import json, datetime; ... mark complete ..."
```

---

## Notes for Human Operators

- All coordination files are in project root
- Agents should be run with `--agent-id <prefix>` for identification
- Human can manually edit WORK_QUEUE.json to inject tasks
- Stale agents auto-marked after 2 minutes no heartbeat
- Lock files auto-expire after 5 minutes