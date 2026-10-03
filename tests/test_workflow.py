import tempfile, unittest
from pathlib import Path
from src.repository import Repository
from src.service import Service
from src.rules import NOTICE_BOUND_STATES, STATES, TRANSITION_ROLES
class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def test_complete_workflow_and_audit(self):
        item=self.service.create_item({"title":"workflow item","description":"complete business flow","severity":'warning',"quantity":12,"threshold":6,"external_ref":"WF-1","bridge_ref":"BR-1"},"creator",'sensor_operator')
        self.assertEqual(item["status"],STATES[0])
        notice=self.service.create_notice({"bridge_ref":"BR-1","title":"限行通告","detail":"荷载管制","notice_no":"NT-1"},"officer",'traffic_authority')
        self.service.add_record(item["id"],{"kind":"evidence","detail":"evidence registered","status":"closed","external_ref":"EV-1"},"recorder",'sensor_operator')
        current=item
        for target in STATES[1:]:
            notice_id=notice["id"] if target in NOTICE_BOUND_STATES else None
            current=self.service.transition(current["id"],target,current["version"],"reviewer",TRANSITION_ROLES[target][0],notice_id=notice_id)
        self.assertEqual(current["status"],STATES[-1])
        self.assertEqual(len(self.service.list_records(current["id"],"viewer")),1)
        events=self.service.audit("viewer",current["id"]); self.assertGreaterEqual(len(events),len(STATES)+1); self.assertTrue(self.repo.verify_audit_chain())
if __name__=="__main__": unittest.main()
