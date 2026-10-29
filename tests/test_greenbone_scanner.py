from __future__ import annotations

from contextlib import contextmanager

import pytest
from gvm.transforms import EtreeCheckCommandTransform

from vulnflux.errors import ErrorKind, VFError
from vulnflux.greenbone.scanner import GreenboneClient, parse_report, target_name, task_name, threat_to_severity
from vulnflux.models import Host

T = EtreeCheckCommandTransform()


def x(s: str):
    return T(s.encode())


REPORT_XML = """<get_reports_response status="200" status_text="OK">
<report id="r1" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5">
  <report id="r1">
    <scan_run_status>Done</scan_run_status>
    <hosts><count>1</count></hosts>
    <results>
      <result id="1"><name>SSL/TLS: Deprecated TLSv1.0</name><host>10.0.0.1</host><port>443/tcp</port><threat>Medium</threat></result>
      <result id="2"><name>OpenSSH old</name><host>10.0.0.1</host><port>22/tcp</port><threat>High</threat></result>
      <result id="3"><name>Info</name><host>10.0.0.1</host><port>general/tcp</port><threat>Log</threat></result>
    </results>
  </report>
</report>
</get_reports_response>"""


def test_parse_report_extrai_report_exterior():
    data = parse_report(x(REPORT_XML))
    assert data.scan_run_status == "Done" and data.results_total == 3 and data.hosts_scanned == 1
    assert data.by_threat == {"Medium": 1, "High": 1, "Log": 1}
    assert data.xml.startswith(b"<?xml") and b'<report id="r1" format_id=' in data.xml
    assert threat_to_severity(data.by_threat) == {"Critical": 0, "High": 1, "Medium": 1, "Low": 0, "Info": 1}


def test_parse_report_sem_report():
    with pytest.raises(VFError):
        parse_report(x('<get_reports_response status="200" status_text="OK"/>'))


class FakeGmp:
    def __init__(self, targets="", tasks=""):
        self.targets, self.tasks = targets, tasks
        self.created_targets, self.created_tasks, self.modified = [], [], []

    def authenticate(self, u, p):
        return x('<authenticate_response status="200" status_text="OK"/>')

    def get_targets(self, filter_string):
        return x(f'<get_targets_response status="200" status_text="OK">{self.targets}</get_targets_response>')

    def create_target(self, name, **kw):
        self.created_targets.append((name, kw))
        return x('<create_target_response status="201" status_text="OK" id="t-new"/>')

    def get_tasks(self, filter_string):
        return x(f'<get_tasks_response status="200" status_text="OK">{self.tasks}</get_tasks_response>')

    def create_task(self, name, **kw):
        self.created_tasks.append((name, kw))
        return x('<create_task_response status="201" status_text="OK" id="task-new"/>')

    def modify_task(self, task_id, **kw):
        self.modified.append((task_id, kw))
        return x('<modify_task_response status="200" status_text="OK"/>')


def client_with(settings, gmp):
    @contextmanager
    def factory(s):
        yield gmp

    return GreenboneClient(settings, gmp_factory=factory)


def test_ensure_task_cria_target_e_task(settings):
    host = Host(name="www.exemplo.pt", scan_target="10.0.0.9", greenbone_enabled=True)
    gmp = FakeGmp()
    assert client_with(settings, gmp).ensure_task(host) == "task-new"
    name, kw = gmp.created_targets[0]
    assert name == target_name(host) and name.startswith("vulnflux:www.exemplo.pt:")
    assert kw["hosts"] == ["10.0.0.9"]
    tname, tkw = gmp.created_tasks[0]
    assert tname == task_name(host) and tkw["target_id"] == "t-new"


def test_ensure_task_reaproveita_e_corrige_target(settings):
    host = Host(name="a.pt", greenbone_enabled=True)
    gmp = FakeGmp(
        targets='<target id="t-1"><name>x</name></target>',
        tasks=f'<task id="k-1"><status>Done</status><target id="t-antigo"/><config id="{settings.greenbone_scan_config_id}"/></task>',
    )
    assert client_with(settings, gmp).ensure_task(host) == "k-1"
    assert gmp.created_targets == [] and gmp.created_tasks == []
    assert gmp.modified == [("k-1", {"target_id": "t-1"})]


def test_ensure_task_ativa_e_transitorio(settings):
    gmp = FakeGmp(targets='<target id="t-1"/>', tasks='<task id="k-1"><status>Running</status></task>')
    with pytest.raises(VFError) as exc:
        client_with(settings, gmp).ensure_task(Host(name="a.pt", greenbone_enabled=True))
    assert exc.value.kind is ErrorKind.TRANSIENT


def test_sessao_sem_password(settings):
    s = settings.model_copy(update={"greenbone_password": type(settings.greenbone_password)("")})
    with pytest.raises(VFError) as exc, GreenboneClient(s).session():
        pass
    assert exc.value.kind is ErrorKind.CONFIG


def test_sessao_socket_inexistente(settings):
    s = settings.model_copy(update={"greenbone_socket": "/nao/existe.sock"})
    with pytest.raises(VFError) as exc, GreenboneClient(s).session():
        pass
    assert exc.value.kind is ErrorKind.DEPENDENCY


def test_task_ativa_traz_o_report_em_curso(settings):
    from vulnflux.greenbone.scanner import TaskBusy

    gmp = FakeGmp(
        targets='<target id="t-1"/>',
        tasks='<task id="k-1"><status>Running</status><current_report><report id="r-9"/></current_report></task>',
    )
    with pytest.raises(TaskBusy) as exc:
        client_with(settings, gmp).ensure_task(Host(name="a.pt", greenbone_enabled=True))
    assert (exc.value.task_id, exc.value.report_id, exc.value.status) == ("k-1", "r-9", "Running")
    assert exc.value.kind is ErrorKind.TRANSIENT
