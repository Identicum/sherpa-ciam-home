import json

def get_data():
    try:
        with open('/data/data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # In a real app, you might want to log this error or handle it differently
        return {}
    except json.JSONDecodeError:
        # Handle cases where JSON is invalid
        return {}

def getRealms():
    data = get_data()
    return list(data.get("realms", {}).keys())

def getEnvironments(): # Renamed from get_environments to match existing call in main.py
    data = get_data()
    return list(data.get("environments", {}).keys())
