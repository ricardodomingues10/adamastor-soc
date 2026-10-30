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

    # perfil rápido: lista de portas e config próprias
    port_lists = ""
    configs = ""
    config_fails = False

    def get_port_lists(self, filter_string):
        return x(f'<get_port_lists_response status="200" status_text="OK">{self.port_lists}</get_port_lists_response>')

    def create_port_list(self, name, port_range, **kw):
        self.created_port_list = (name, port_range)
        return x('<create_port_list_response status="201" status_text="OK" id="pl-fast"/>')

    def get_scan_configs(self, filter_string):
        return x(f'<get_configs_response status="200" status_text="OK">{self.configs}</get_configs_response>')

    def create_scan_config(self, base, name, **kw):
        if self.config_fails:
            from gvm.errors import GvmResponseError

            raise GvmResponseError("400", "sem permissão")
        self.created_config = (base, name)
        return x('<create_config_response status="201" status_text="OK" id="cfg-fast"/>')

    def get_preferences(self, nvt_oid, config_id):
        return x(
            '<get_preferences_response status="200" status_text="OK"><preference><nvt oid="1.3.6.1.4.1.25623.1.0.12288"/>'
            "<id>5</id><name>Enable CGI scanning</name><type>checkbox</type><value>yes</value></preference>"
            "<preference><id>6</id><name>Outra</name><type>entry</type></preference></get_preferences_response>"
        )

    def modify_scan_config_set_nvt_preference(self, config_id, name, nvt_oid, value=None):
        self.set_prefs = getattr(self, "set_prefs", []) + [(config_id, name, value)]
        return x('<modify_config_response status="200" status_text="OK"/>')


def client_with(settings, gmp):
    @contextmanager
    def factory(s):
        yield gmp

    return GreenboneClient(settings, gmp_factory=factory)


def test_ensure_task_cria_target_e_task(settings):
    host = Host(name="www.exemplo.pt", scan_target="10.0.0.9", greenbone_enabled=True, greenbone_profile="completo")
    gmp = FakeGmp()
    assert client_with(settings, gmp).ensure_task(host) == "task-new"
    name, kw = gmp.created_targets[0]
    assert name == target_name(host) and name.startswith("vulnflux:www.exemplo.pt:")
    assert kw["hosts"] == ["10.0.0.9"] and kw["port_list_id"] == settings.greenbone_port_list_id
    tname, tkw = gmp.created_tasks[0]
    assert tname == task_name(host) and tkw["target_id"] == "t-new"
    assert tkw["config_id"] == settings.greenbone_scan_config_id and tkw["preferences"] == {"max_checks": "10"}


def test_perfil_rapido_cria_portas_e_config(settings):
    host = Host(name="www.exemplo.pt", greenbone_enabled=True)  # sem perfil = VF_GREENBONE_PROFILE (rapido)
    gmp = FakeGmp()
    client = client_with(settings, gmp)
    client.ensure_task(host)
    assert client.last_profile == "rapido" and client.notes == []
    assert gmp.created_port_list[0].startswith("vulnflux:portas-comuns:") and "T:20-23" in gmp.created_port_list[1]
    assert gmp.created_config == (settings.greenbone_scan_config_id, "VulnFlux · rápido")
    assert gmp.set_prefs == [("cfg-fast", "1.3.6.1.4.1.25623.1.0.12288:5:checkbox:Enable CGI scanning", "no")]
    assert gmp.created_targets[0][1]["port_list_id"] == "pl-fast"
    assert gmp.created_tasks[0][1]["config_id"] == "cfg-fast"
    assert target_name(host, "rapido") != target_name(host, "completo")


def test_perfil_rapido_reaproveita_e_recua_se_o_gvmd_recusar(settings):
    host = Host(name="a.pt", greenbone_enabled=True)
    gmp = FakeGmp()
    gmp.port_lists = '<port_list id="pl-old"/>'
    gmp.config_fails = True
    client = client_with(settings, gmp)
    client.ensure_task(host)
    assert not hasattr(gmp, "created_port_list") and gmp.created_targets[0][1]["port_list_id"] == "pl-old"
    assert gmp.created_tasks[0][1]["config_id"] == settings.greenbone_scan_config_id
    assert "Full and fast" in client.notes[0]


def test_ensure_task_reaproveita_e_corrige_target(settings):
    host = Host(name="a.pt", greenbone_enabled=True, greenbone_profile="completo")
    gmp = FakeGmp(
        targets='<target id="t-1"><name>x</name></target>',
        tasks=f'<task id="k-1"><status>Done</status><target id="t-antigo"/><config id="{settings.greenbone_scan_config_id}"/></task>',
    )
    assert client_with(settings, gmp).ensure_task(host) == "k-1"
    assert gmp.created_targets == [] and gmp.created_tasks == []
    assert gmp.modified == [("k-1", {"target_id": "t-1", "preferences": {"max_checks": "10"}})]


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
