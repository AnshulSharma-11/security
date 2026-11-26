import os
import tempfile

_d = tempfile.mkdtemp()
os.environ["SENTINEL_SECRET_KEY"] = "test-secret-key-0123456789-abcdefghijklmnop"
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{_d}/test.db"
os.environ["SENTINEL_EAGER"] = "true"
