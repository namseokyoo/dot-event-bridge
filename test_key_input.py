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
        with tempfile.TemporaryDirectory(dir=Path(__file__).absolute().parent) as temp:
            base=Path(temp); synthetic=json.dumps({'key':'SYNTHETIC-NOT-A-REAL-CREDENTIAL','confirmed':True}).encode()
            receive(io.BytesIO(synthetic),base)
            self.assertEqual((base/'ops').stat().st_mode & 0o777,0o700)
            self.assertEqual((base/'ops/runtime-key').stat().st_mode & 0o777,0o600)
            receive(io.BytesIO(json.dumps({'key':'SYNTHETIC-REPLACEMENT-CREDENTIAL','confirmed':True}).encode()),base)
            self.assertEqual((base/'ops/runtime-key').read_text(),'SYNTHETIC-REPLACEMENT-CREDENTIAL\n')
            self.assertEqual(list((base/'ops').glob('.runtime-key-*')),[])
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
        with tempfile.TemporaryDirectory(dir=Path(__file__).absolute().parent) as temp:
            base=Path(temp); (base/'destination').mkdir(); (base/'ops').symlink_to(base/'destination',target_is_directory=True)
            with self.assertRaises(ValueError): receive(io.BytesIO(json.dumps({'key':'SYNTHETIC-DIRECTORY-CHECK','confirmed':True}).encode()),base)

    def test_invalid_submission_preserves_existing_value(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).absolute().parent) as temp:
            base=Path(temp)
            receive(io.BytesIO(json.dumps({'key':'SYNTHETIC-ORIGINAL-CREDENTIAL','confirmed':True}).encode()),base)
            with self.assertRaises(ValueError): receive(io.BytesIO(b'{"key":"bad","confirmed":true}'),base)
            self.assertEqual((base/'ops/runtime-key').read_text(),'SYNTHETIC-ORIGINAL-CREDENTIAL\n')
    def test_atomic_replace_failure_preserves_original(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).absolute().parent) as temp:
            base=Path(temp)
            payload=json.dumps({'key':'SYNTHETIC-ORIGINAL-CREDENTIAL','confirmed':True}).encode()
            receive(io.BytesIO(payload),base)
            with patch('runtime_key_receive.os.replace',side_effect=OSError('Synthetic failure')):
                with self.assertRaises(OSError):receive(io.BytesIO(payload),base)
            self.assertEqual((base/'ops/runtime-key').read_text(),'SYNTHETIC-ORIGINAL-CREDENTIAL\n')
            self.assertEqual(list((base/'ops').glob('.runtime-key-*')),[])
    def test_ssh_failure_never_puts_key_in_arguments(self):
        from types import SimpleNamespace
        value='SYNTHETIC-LOCAL-INPUT-ONLY'
        with patch('sys.argv',['helper','--ssh-host','example-alias','--remote-dir','/example/project']),patch.object(input_helper.resource,'setrlimit'),patch.object(input_helper.sys.stdin,'isatty',return_value=True),patch.object(input_helper.sys.stderr,'isatty',return_value=True),patch('builtins.input',side_effect=['YES','YES']),patch.object(input_helper,'hidden',return_value=value),patch.object(input_helper.subprocess,'run',return_value=SimpleNamespace(returncode=255)) as run:
            with self.assertRaises(ValueError): input_helper.main()
            self.assertNotIn(value,str(run.call_args.args))
            self.assertIn(value.encode(),run.call_args.kwargs['input'])
            self.assertIn('StrictHostKeyChecking=yes',run.call_args.args[0])
    def test_destination_symlink_refused(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).absolute().parent) as temp:
            base=Path(temp); (base/'ops').mkdir(mode=0o700); (base/'untouched').write_text('Synthetic preserved')
            (base/'ops/runtime-key').symlink_to(base/'untouched')
            payload=json.dumps({'key':'SYNTHETIC-NEW-CREDENTIAL','confirmed':True}).encode()
            with self.assertRaises(ValueError): receive(io.BytesIO(payload),base)
            self.assertEqual((base/'untouched').read_text(),'Synthetic preserved')
