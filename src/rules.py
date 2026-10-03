from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='桥梁结构监测与限行决策'; ENTITY='桥梁告警'; ID_PREFIX='BM'
SEVERITIES=['normal', 'watch', 'warning', 'critical']; STATES=['normal', 'warning', 'restricted', 'closed', 'restored']; TRANSITIONS={'normal': ['warning'], 'warning': ['restricted'], 'restricted': ['closed'], 'closed': ['restored'], 'restored': []}; TRANSITION_ROLES={'warning': ['sensor_operator'], 'restricted': ['bridge_engineer'], 'closed': ['traffic_authority'], 'restored': ['bridge_engineer']}
CREATE_ROLES=set(['sensor_operator']); RECORD_ROLES=set(['sensor_operator', 'bridge_engineer']); AUDIT_ROLES=set(['bridge_engineer', 'viewer']); VIEW_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority', 'viewer'])
SEVERITY_WEIGHT={'normal': 1.0, 'watch': 3.0, 'warning': 6.0, 'critical': 9.0}; DEADLINE_HOURS={'normal': 72, 'watch': 24, 'warning': 8, 'critical': 4}; TERMINAL_STATES=set(['restored'])
# 预警确认后可直接恢复结案，不必先走限行再解封
TRANSITIONS['warning']=['restricted','restored']
# --- 桥梁值守批次链接入 ---
BATCH_STATUSES=('pending','processed','rejected','archived')
NOTICE_STATUSES=('active','withdrawn')
NOTICE_LEVELS=('restriction','closure')
BATCH_ROLES=set(['sensor_operator','bridge_engineer'])
BRIDGE_MANAGE_ROLES=set(['bridge_engineer'])
NOTICE_MANAGE_ROLES=set(['traffic_authority','bridge_engineer'])
# 限行/封闭必须绑定同一座桥仍有效的交通通告
NOTICE_BIND_STATES=('restricted','closed')
# 通告撤回或事项变化后，已升级告警退回的状态
NOTICE_ROLLBACK_TARGET='warning'
def reading_severity(value,threshold):
    """单次监测读数按超值比分档：>=1 超限 critical，>=0.8 warning，>=0.6 watch。"""
    ratio=value/threshold if threshold>0 else 1.0
    if ratio>=1.0: return 'critical'
    if ratio>=0.8: return 'warning'
    if ratio>=0.6: return 'watch'
    return 'normal'
def covers_level(notice_level,target_state):
    """closure 通告覆盖封闭+限行，restriction 通告只覆盖限行。"""
    if notice_level=='closure': return target_state in ('restricted','closed')
    if notice_level=='restriction': return target_state=='restricted'
    return False
def max_severity(current,candidate):
    """告警等级单调：只升不降。"""
    return candidate if SEVERITY_WEIGHT.get(candidate,0)>SEVERITY_WEIGHT.get(current,0) else current
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))
