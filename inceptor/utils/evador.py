# -*- coding: utf-8 -*-

from io import UnsupportedOperation
import os
import shutil
import random
import string

from encoders.EncoderChain import EncoderChain
from engine.modules.TemplateModule import TemplateModule
from generators.DotNetArtifactGenerator import DotNetArtifactGenerator
from generators.NativeArtifactGenerator import NativeArtifactGenerator
from generators.PowerShellArtifactGenerator import PowerShellArtifactGenerator
from utils.ThreatCheck import ThreatCheck
from utils.utils import isDotNet

TRANSFORMERS = ["loader", "donut", "pe2sh", "srdi"]
ARCHITECTURES = ['x86', 'x64']

# Generate handling class
class Evador:
    def __init__(self, safe_directory):
        self.generator = None
    
    # Set generate method as private
    def __generate(self, target_path, check=False):
        self.generator.generate()
        
        if check:
            return self.validate(target_path)
        
        return target_path
    
    def __validate_common_params(self, binary_path, data):
        params = dict()

        (filename, ext) = os.path.splitext(binary_path)
        # Auto correct ext if bin is set
        if ext == "bin":
            shutil.copy(binary_path, filename + ".raw")
        
        # Outfile should not be managed by user
        params['outfile'] = data.get('outfile')
        
        # Lookup standard params
        params['check'] = bool(data.get('check', False))
        params['sgn'] = bool(data.get('sgn', False))
        params['process'] = data.get('process')
        params['delay'] = int(data.get('delay', 0))
        params['chain'] = EncoderChain.from_list(data.get('encoder'))
        # Set transformer params
        params['params'] = bool(data.get('transformer_params', False))
        params['pinject'] = bool(data.get('pinject', False))
        params['obfuscate'] = bool(data.get('obfuscate', False))
        # This param is mandatory ONLY for .NET DLLs
        params['classname'] = bool(data.get('classname', False)) 
        # This param is mandatory ONLY for .NET DLLs
        params['function'] = bool(data.get('function', False))

        modules = set(data.get('modules', []))
        # Update module list based on user params
        if params['delay'] > 0:
            modules.add('delay')
        if params['process'] is not None:
            modules.add('find_process')
        
        params['modules'] = [str(m).strip() for m in modules]
        params['transformer'] = data.get('transformer')
        if params['transformer'] not in TRANSFORMERS:
            raise UnsupportedOperation('Invalid transformer param')
        
        if params['process'] is None:
            raise UnsupportedOperation('Missing process name params')
        
        params['arch'] = data.get('arch', 'x64')
        if params['arch'] not in ARCHITECTURES:
            raise UnsupportedOperation('Invalid architecture param')
        
        return params
    
    def __validate_binary_params(self, binary_path, data):
        # Validate standard params first
        params = self.__validate_common_params(binary_path, data)
        
        params['hide_window'] = bool(data.get('hide_window', False))
        params['clone'] = data.get('clone')
        params['sign'] = bool(data.get('sign', False))
        params['domain'] = data.get('domain')
        params['offline'] = bool(data.get('offline', False))
        params['steal_from'] = data.get('steal_from')
        
        return params
    
    def __get_random_name(self, k=24):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=k))
    
    def generate_target_path(self, target_dir):
        target_file = os.path.join(target_dir, f"target_{self.__get_random_name(24)}")
        while os.path.exists(target_file):
            target_file = os.path.join(target_dir, f"target_{self.__get_random_name(24)}")
        
        return target_file
    
    def list_modules(self):
        return TemplateModule.all_modules()
    
    def validate(self, binary_path):
        threat_check = ThreatCheck()
        return threat_check.check(binary_path)
    
    def generate_native(self, binary_path, data):
        # Lookup Binary params
        params = self.__validate_binary_params(binary_path, data)
        
        params['dll'] = bool(data.get('dll', False))
        params['exports'] = data.get('exports')
        
        params['compiler'] = data.get('compiler', 'cl')
        if params['compiler'] not in ['cl', 'clang', 'llvm']:
            raise UnsupportedOperation('Invalid compiler param')
        
        (_, ext) = os.path.splitext(binary_path)
        if ext == "dll" and not isDotNet(binary_path) and not params.get('function', False):
            raise UnsupportedOperation("Native DLLs require to specify an exported function")
        
        self.generator = NativeArtifactGenerator(binary_path, **params)
        return self.__generate(params['outfile'], check=params['check'])
    
    def generate_dotnet(self, binary_path, data):
        # Lookup Binary params
        params = self.__validate_binary_params(binary_path, data)
        
        (_, ext) = os.path.splitext(binary_path)
        if ext == "dll" and isDotNet(binary_path) and not (params.get('function', False) and params.get('classname', False)):
            raise UnsupportedOperation(".NET DLLs require to specify both class and method names")

        self.generator = DotNetArtifactGenerator(binary_path, **params)
        return self.__generate(params['outfile'], check=params['check'])
    
    def generate_powershell(self, binary_path, data):
        # Lookup Common params
        params = self.__validate_common_params(binary_path, data)
        
        self.generator = PowerShellArtifactGenerator(binary_path, **params)
        return self.__generate(params['outfile'], check=params['check'])