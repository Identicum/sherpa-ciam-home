import importlib
from flask import Flask, Blueprint, render_template
import os
import utils

app = Flask(__name__)


# Load messages at startup
MESSAGES = utils.load_messages()


# Context processor to inject messages into all templates
@app.context_processor
def inject_messages():
    return dict(messages=MESSAGES)


@app.route('/', methods=["GET"])
def index():
    return render_template(
        "index.html",
        utils=utils
    )


@app.route('/health', methods=["GET"])
def getHealth():
    return 'OK'


# Dynamically load blueprints from ./blueprints dir
blueprints_dir = 'blueprints'
blueprint_path = os.path.join(os.path.dirname(__file__), blueprints_dir)

for filename in os.listdir(blueprint_path):
    if filename.endswith('.py') and not filename.startswith('__'):
        module_name = filename[:-3]
        try:
            module = importlib.import_module(f'blueprints.{module_name}')
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, Blueprint):
                    app.register_blueprint(attr)
                    print(f"Blueprint '{attr.name}' registered from {filename}")
                    break
        except Exception as e:
            print(f"Error loading {filename}: {e}")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
