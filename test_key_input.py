import getpass
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import runtime_key_input as input_helper
from runtime_key_receive import receive

class KeyInput(unittest.TestCase):
    def test_receiver_exclusive_private_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp); synthetic=json.dumps({'key':'SYNTHETIC-NOT-A-REAL-CREDENTIAL'}).encode()
            receive(io.BytesIO(synthetic),base)
            self.assertEqual((base/'ops').stat().st_mode & 0o777,0o700)
            self.assertEqual((base/'ops/runtime-key').stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError): receive(io.BytesIO(synthetic),base)
    def test_noninteractive_input_refused(self):
        with patch.object(input_helper.sys.stdin,'isatty',return_value=False),patch.object(input_helper.getpass,'getpass') as ask:
            with self.assertRaises(ValueError): input_helper.hidden()
            ask.assert_not_called()
    def test_echo_fallback_refused(self):
        def fallback(*a):
            warnings.warn('No echo control',getpass.GetPassWarning)
            self.fail('Unsafe input fallback')
        with patch.object(input_helper.sys.stdin,'isatty',return_value=True),patch.object(input_helper.sys.stderr,'isatty',return_value=True),patch.object(input_helper.os,'open',return_value=99),patch.object(input_helper.os,'close'),patch.object(input_helper.termios,'tcgetattr'),patch.object(input_helper.getpass,'getpass',side_effect=fallback):
            with self.assertRaises(getpass.GetPassWarning): input_helper.hidden()
    def test_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp); (base/'destination').mkdir(); (base/'ops').symlink_to(base/'destination',target_is_directory=True)
            with self.assertRaises(ValueError): receive(io.BytesIO(b'{}'),base)
