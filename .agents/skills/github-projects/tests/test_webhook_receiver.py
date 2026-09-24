import hashlib, hmac, json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import webhook_receiver

class ReceiverTests(unittest.TestCase):
    def test_signature(self):
        secret, body = b"secret", b'{"action":"opened"}'
        sig = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        self.assertTrue(webhook_receiver.verify(secret, body, sig)); self.assertFalse(webhook_receiver.verify(secret, b"bad", sig))
    def test_delivery_is_idempotent_and_versioned(self):
        with tempfile.TemporaryDirectory() as d:
            db = webhook_receiver.db_open(Path(d) / "deliveries.sqlite3"); payload={"repository":{"full_name":"S2Forge/systems"}}
            self.assertTrue(webhook_receiver.enqueue(db,"d1","issues",payload)); self.assertFalse(webhook_receiver.enqueue(db,"d1","issues",payload))
            envelope=json.loads(db.execute("SELECT payload FROM deliveries WHERE delivery_id='d1'").fetchone()[0]); self.assertEqual(envelope["schema_version"],webhook_receiver.EVENT_VERSION)

if __name__ == "__main__": unittest.main()
