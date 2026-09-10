import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('configure', Path(__file__).parents[1] / 'configure.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ConfigurationTests(unittest.TestCase):
    def test_networkless_configuration(self):
        self.assertEqual(module.validate_config({}), ('', '', {}))

    def test_rejects_actual_credentials_and_env_injection(self):
        for env in ({'GH_TOKEN': 'real-secret'}, {'LD_PRELOAD': '/workspace/evil.so'}, {'PATH': '/workspace'}):
            with self.assertRaises(ValueError):
                module.validate_config({'env': env})

    def test_rejects_proxy_redirection(self):
        for url in ('http://token@localhost:3128', 'https://token@127.0.0.1:3128',
                    'http://token@127.0.0.1:9999', 'http://token@127.0.0.1:3128/path'):
            with self.assertRaises(ValueError):
                module.validate_config({'proxyUrl': url, 'ca': 'invalid'})

    def test_ca_and_proxy_required_together(self):
        for value in ({'ca': 'certificate'}, {'proxyUrl': 'http://token@127.0.0.1:3128'},
                      {'env': {'GH_TOKEN': module.SENTINEL}}):
            with self.assertRaises(ValueError):
                module.validate_config(value)
