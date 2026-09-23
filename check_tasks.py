import json
with open('C:/Users/purpl/Desktop/downpour_consolidated/WORK_QUEUE.json', 'r') as f:
    data = json.load(f)
for task in data['tasks']:
    if task['status'] != 'completed':
        print(f"{task['id']}: {task['title']} - {task['status']}")