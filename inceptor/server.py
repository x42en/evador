#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from plistlib import InvalidFileException
import sys
import yaml
import tempfile

from flask import Flask
from phk_logger import PHKLogger as Logger

from routes.publicAPI import public_api
from utils.evador import Evador

VERBOSE   = True
CONF_FILE = 'config.yaml'

# Ensure config file exists
if not os.path.isfile(CONF_FILE):
    raise FileExistsError('Config file does not exists')

# Open and load config file
with open(CONF_FILE, 'rt') as stream:
    try:
        config = yaml.safe_load(stream)
    except Exception as err:
        raise InvalidFileException(f"Invalid YAML file: {err}")

try:
    # Start Web app
    app = Flask(__name__)
    app.secret_key = bytes(config['app']['secret_key'].encode('utf-8'))
except Exception as err:
    raise RuntimeError(f"Unable to start Flask app: {err}")

try:
    if 'flask' in config.keys():
        app.config['UPLOAD_FOLDER'] = config['flask'].get('UPLOAD_FOLDER', tempfile.gettempdir())
        # Set max upload to 10Mo by default
        app.config['MAX_CONTENT_PATH'] = config['flask'].get('MAX_CONTENT_PATH', 1048576)
except Exception as err:
    raise RuntimeError(f"Unable to configure Flask app: {err}")

try:
    # Generate logger object
    logger = Logger(config['app']['log_file'], config['app']['log_level'], name="evador")
    logger.debug('Logger set')
except Exception as err:
    raise RuntimeError(f"Unable to setup logger: {err}")

# Register Generators
with app.app_context():
    # Should register with a safe directory
    app.evador = Evador(config['app']['safe_directory'])
    logger.debug('Evador app loaded')

try:
    # Register API routes
    app.register_blueprint(public_api)
    logger.debug('Evador Blueprint loaded')
except Exception as err:
    raise RuntimeError(f"Unable to register routes: {err}")

if __name__ == '__main__':
    try:
        logger.warning('REST API started manually...')
        app.run()
    except (SystemExit, KeyboardInterrupt):
        logger.info('Exit by user')
        sys.exit(0)
    except Exception as err:
        logger.info(f"Error occured: {err}")
        sys.exit(1)