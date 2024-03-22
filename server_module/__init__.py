from flask import Flask
from diffiehellman_utils.dh_utils import DiffieHellmanUtils


def create_app():
    app = Flask(__name__)

    dh_utils = DiffieHellmanUtils()
    app.dh_parameters = {'prime': None, 'generator': None}
    app.dh_parameters['prime'], app.dh_parameters['generator'] = dh_utils.generate_base_and_prime()

    app.users = {}
    app.messages = {}

    from .relay_server import setup_routes
    setup_routes(app)

    return app
