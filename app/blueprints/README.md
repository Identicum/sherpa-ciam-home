# Dynamically load blueprint

This application automatically discovers and registers Flask blueprints from the `blueprints/` directory at startup.

## Adding a new Blueprint

To add a new blueprint, create a `.py` file in the `blueprints/` directory following these requirements:

### Requirements

1. **Filename**: Must end with `.py` and cannot start with `__` (e.g., `__init__.py` is ignored)
2. **Blueprint object**: Must contain at least one Flask Blueprint instance
3. **Standard structure**: Follow Flask blueprint conventions

### Blueprint Template
```python
from flask import Blueprint, jsonify, request

# Create the blueprint (use kebab-case for the name)
my_feature_bp = Blueprint('my-feature', __name__)

@my_feature_bp.route('/my-endpoint', methods=['GET'])
def get_data():
    return jsonify({'message': 'Hello from my feature!'})

@my_feature_bp.route('/my-endpoint', methods=['POST'])
def create_data():
    data = request.json
    return jsonify({'received': data}), 201