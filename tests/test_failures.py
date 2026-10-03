import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied
from src.repository import Repository
from src.service import Service
from src.rules import NOTICE_BOUND_STATES, STATES, TRANSITION_ROLES
class FailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
        self.item=self.service.create_item({"title":"failure item","description":"failure scenarios","severity":'warning',"quantity":5,"threshold":10,"external_ref":"FAIL-1","bridge_ref":"BR-F"},"creator",'sensor_operator')
        self.notice=self.service.create_notice({"bridge_ref":"BR-F","title":"管制通告","detail":"管制措施","notice_no":"NF-1"},"officer",'traffic_authority')
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def test_permission_version_duplicate_and_invariant(self):
        with self.assertRaises(PermissionDenied): self.service.transition(self.item["id"],STATES[1],1,"attacker","viewer")
        with self.assertRaises(ConflictError): self.service.transition(self.item["id"],STATES[1],99,"reviewer",TRANSITION_ROLES[STATES[1]][0])
        payload={"kind":"action","detail":"same reference","status":"open","external_ref":"DUP-1"}
        self.service.add_record(self.item["id"],payload,"recorder",'sensor_operator')
        with self.assertRaises(ConflictError): self.service.add_record(self.item["id"],payload,"recorder",'sensor_operator')
        current=self.service.get_item(self.item["id"],"viewer")
        for target in STATES[1:-1]:
            notice_id=self.notice["id"] if target in NOTICE_BOUND_STATES else None
            current=self.service.transition(current["id"],target,current["version"],"reviewer",TRANSITION_ROLES[target][0],notice_id=notice_id)
        with self.assertRaises(ConflictError): self.service.transition(current["id"],STATES[-1],current["version"],"reviewer",TRANSITION_ROLES[STATES[-1]][0])
if __name__=="__main__": unittest.main()
