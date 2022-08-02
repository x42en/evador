# -*- coding: utf-8 -*-

import os
import io
from black import InvalidInput

from flask import jsonify
from flask import request
from flask import g as global_vars
from flask import current_app
from flask import Blueprint
from flask import send_file

from werkzeug.utils import secure_filename

public_api = Blueprint('public_api', __name__)

def send_error(msg):
    """Send back error in json
    """
    return jsonify({'status': 'error', 'message': str(msg)})

def send_binary(binary_path):
    # Load target file in memory
    return_data = io.BytesIO()
    with open(binary_path, 'rb') as fo:
        return_data.write(fo.read())
    
    # Reset cursor
    return_data.seek(0)

    # Unlink file
    os.remove(binary_path)

    # Send it back to user
    return send_file(return_data, mimetype="binary/octet-stream")

@public_api.before_request
def before_request_callback():
    # Get standard vars
    method = request.method
    path = request.path

    # Set init vars
    source_name = None
    binary_path = None
    dest_path = None

    # On binary manipulation only
    if method == 'POST' and path in ['/test', '/check', '/native', '/dotnet', '/powershell']:
        try:
            # Retrieve file from user
            f = request.files['binary']
            source_name = secure_filename(f.filename)
            if source_name == '':
                raise InvalidInput('Invalid source file name')
            
            # Store file in upload directory
            binary_path = os.path.abspath(os.path.join(current_app.config['UPLOAD_FOLDER'], f"source_{source_name}"))
            f.save(binary_path)
        except Exception as err:
            return send_error(f"Unable to save source file: {err}")
        
        try:
            # Generate output path
            dest_path = current_app.evador.generate_target_path(current_app.config['UPLOAD_FOLDER'])
        except Exception as err:
            return send_error(f"Unable to generate target file name: {err}")        

    # Register var in context
    global_vars.source_name = source_name
    global_vars.binary_path = binary_path
    global_vars.dest_path = dest_path

@public_api.route('/modules', methods=['GET'])
def list_modules():
    try:
        modules = current_app.evador.list_modules()
    except Exception as err:
        return send_error(err)
    
    return jsonify({'status': 'success', 'data': modules})

@public_api.route('/check', methods=['POST'])
def check_file():
    try:
        result = current_app.evador.validate(global_vars.binary_path)
    except Exception as err:
        return send_error(err)
    
    return jsonify({'status': 'success', 'data': result})

@public_api.route('/native', methods=['POST'])
def evade_native():
    data = request.form.to_dict()
    # Override outfile
    data['outfile'] = global_vars.dest_path
    
    try:
        current_app.evador.generate_native(global_vars.binary_path, data)
    except Exception as err:
        return send_error(err)
    
    return send_binary(data['outfile'])

@public_api.route('/dotnet', methods=['POST'])
def evade_dotnet():
    data = request.form.to_dict()
    # Override outfile
    data['outfile'] = global_vars.dest_path

    try:
        current_app.evador.generate_dotnet(global_vars.binary_path, data)
    except Exception as err:
        return send_error(err)
    
    return send_binary(data['outfile'])

@public_api.route('/powershell', methods=['POST'])
def evade_powershell():
    data = request.form.to_dict()
    # Override outfile
    data['outfile'] = global_vars.dest_path
    
    try:
        current_app.evador.generate_powershell(global_vars.binary_path, data)
    except Exception as err:
        return send_error(err)
    
    return send_binary(data['outfile'])

