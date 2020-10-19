import json
from pathlib import Path

with (Path("test-results") / Path("final_result.json")).open() as f:
    results = json.loads(f.read())

score = results["overall-result"]["score"]
max_score = results["overall-result"]["max_score"]

if score != max_score:
    print(f"Did not receive max score. {score}/{max_score}")
    exit(-1)
else:
    print(f"Got max score. {score}/{max_score}")
    exit(0)