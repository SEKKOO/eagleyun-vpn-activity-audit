"""Offline behavioral tests; no real accounts, cookies or employee data."""
import base64
import csv
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

spec = importlib.util.spec_from_file_location("vpn_audit", Path(__file__).with_name("vpn_audit.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
TZ = ZoneInfo("Asia/Shanghai")


def stamp(value, end=False):
    return v.parse_timestamp(value, TZ, end=end, date_end="inclusive-day")


def traffic(i, total=5):
    return {"employee_id": f"emp_{i}", "access_count": 2, "request_bytes": total,
            "response_bytes": 0, "total_bytes": total}


def person(i, name="测试甲"):
    return {"id": f"emp_{i}", "match_type": "employee", "name": name, "department": []}


def application(begin="2026-10-01", end="2026-10-02", name="测试甲"):
    return {"审批编号": "demo", "申请人": name, "申请项目": "VPN",
            "生效开始": begin, "生效结束": end, "申请时间": "2026-09-25"}


def run_audit(apps, loader, **kwargs):
    settings = dict(tz=TZ, date_end="inclusive-day", window_start=stamp("2026-10-01"),
                    window_end=stamp("2026-10-31", True), as_of=stamp("2026-11-01"),
                    server_end="inclusive", scope_confirmed=True, log_start=stamp("2026-09-01"))
    settings.update(kwargs)
    return v.build_audit(apps, loader, **settings)


def snapshot(start, end, rows=None, people=None, complete=True):
    return {"start": start, "end": end, "complete": complete,
            "rows": [traffic(1)] if rows is None else rows,
            "employees": [person(1)] if people is None else people}


class Paged(v.ConsoleClient):
    def __init__(self, total=234, mutate=None):
        super().__init__()
        self.total, self.calls, self.mutate = total, [], mutate

    def business(self, path, query=None):
        self.calls.append((path, dict(query)))
        page = query["page_num"]
        batch = [traffic(i) for i in range((page - 1) * 10, min(page * 10, self.total))]
        result = {"page_info": {"current_page": page, "page_size": 10, "total_num": self.total}, "rows": batch}
        return self.mutate(page, result) if self.mutate else result


class PaginationTests(unittest.TestCase):
    def test_null_rows_with_explicit_zero_total_is_empty(self):
        def mutate(page, data):
            data["rows"] = None
            return data
        self.assertEqual(Paged(0, mutate).all_stats(1, 2), [])
        with self.assertRaises(v.AuditError):
            Paged(1, mutate).all_stats(1, 2)

    def test_null_response_is_notice_without_inventing_zero_total(self):
        for data in (None, {"rows": None, "page_info": None}):
            with self.subTest(data=data), self.assertRaises(v.EmptyStatistics):
                Paged(0, lambda page, result: data).all_stats(1, 2)

    def test_missing_rows_with_zero_total_is_still_rejected(self):
        def mutate(page, data):
            del data["rows"]
            return data
        with self.assertRaises(v.AuditError):
            Paged(0, mutate).all_stats(1, 2)

    def test_null_later_page_is_incomplete_not_empty_notice(self):
        with self.assertRaises(v.AuditError) as caught:
            Paged(20, lambda page, data: None if page == 2 else data).all_stats(1, 2)
        self.assertNotIsInstance(caught.exception, v.EmptyStatistics)

    def test_schema_diagnostic_never_echoes_values_or_unknown_keys(self):
        data = {"rows": "secret-value", "secret-key": "secret-cookie",
                "data": {"rows": [{"employee_id": "secret-employee"}],
                         "secret-nested-key": "secret-password"}}
        detail = v.statistics_shape(data)
        self.assertNotIn("secret", detail)
        self.assertEqual(json.loads(detail)["fields"]["data"]["fields"]["rows"]["length"], 1)

    def test_full_234_including_last_four(self):
        client = Paged()
        rows = client.all_stats(100, 200)
        self.assertEqual(len(rows), 234)
        self.assertEqual(len(client.calls), 24)
        self.assertEqual(client.calls[-1][1]["page_num"], 24)
        self.assertEqual({(q["start_time"], q["end_time"]) for _, q in client.calls}, {(100, 200)})
        self.assertTrue(all("current_page" not in q for _, q in client.calls))

    def test_zero_rows_is_complete_single_page(self):
        c = Paged(0)
        self.assertEqual(c.all_stats(1, 2), [])
        self.assertEqual(len(c.calls), 1)

    def test_duplicate_page_rejected(self):
        def mutate(page, data):
            if page == 2:
                data["rows"][0]["employee_id"] = "emp_0"
            return data
        with self.assertRaises(v.AuditError):
            Paged(20, mutate).all_stats(1, 2)

    def test_early_empty_page_rejected(self):
        def mutate(page, data):
            if page == 2:
                data["rows"] = []
            return data
        with self.assertRaises(v.AuditError):
            Paged(20, mutate).all_stats(1, 2)

    def test_wrong_page_rejected(self):
        def mutate(page, data):
            data["page_info"]["current_page"] = 1
            return data
        with self.assertRaises(v.AuditError):
            Paged(20, mutate).all_stats(1, 2)

    def test_changing_total_rejected(self):
        def mutate(page, data):
            if page == 2:
                data["page_info"]["total_num"] = 21
            return data
        with self.assertRaises(v.AuditError):
            Paged(20, mutate).all_stats(1, 2)

    def test_missing_flow_not_zero(self):
        def mutate(page, data):
            del data["rows"][0]["total_bytes"]
            return data
        with self.assertRaises(v.AuditError):
            Paged(1, mutate).all_stats(1, 2)


class BusinessTests(unittest.TestCase):
    def test_each_application_uses_own_effective_period(self):
        calls = []
        def loader(a, b):
            calls.append((a, b))
            return snapshot(a, b)
        apps = [application(), application(), application("2026-10-04", "2026-10-05")]
        result = run_audit(apps, loader)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], (stamp("2026-10-01"), stamp("2026-10-02", True) - 1))
        self.assertTrue(all(x["status"] == "核查区间内使用过VPN" for x in result["results"]))

    def test_submit_timestamp_never_replaces_validity(self):
        app = application()
        app["生效开始"] = ""
        result = run_audit([app], lambda *a: self.fail("must not query"))
        self.assertEqual(result["results"][0]["status"], "申请字段异常")

    def test_non_vpn_ignored(self):
        app = application()
        app["申请项目"] = "VPN其他项目"
        result = run_audit([app], lambda *a: self.fail("must not query"))
        self.assertEqual(result["vpn_application_count"], 0)

    def test_future_period_not_unused(self):
        result = run_audit([application("2026-12-01", "2026-12-02")], lambda *a: self.fail("must not query"))
        self.assertEqual(result["results"][0]["status"], "尚未生效")

    def test_failure_not_unused(self):
        def loader(*args):
            raise v.AuditError("模拟失败")
        result = run_audit([application()], loader)
        self.assertEqual(result["results"][0]["status"], "查询不完整或失败")

    def test_incomplete_evidence_not_unused(self):
        result = run_audit([application()], lambda a, b: snapshot(a, b, complete=False))
        self.assertEqual(result["results"][0]["status"], "查询不完整或失败")

    def test_wrong_interval_evidence_rejected(self):
        result = run_audit([application()], lambda a, b: snapshot(a - 1, b))
        self.assertEqual(result["results"][0]["status"], "查询不完整或失败")

    def test_ambiguous_names_not_arbitrary_selection(self):
        result = run_audit([application()], lambda a, b: snapshot(a, b, [traffic(1), traffic(2)], [person(1), person(2)]))
        self.assertEqual(result["results"][0]["status"], "姓名匹配待确认")

    def test_inactive_person_needs_independent_identity(self):
        result = run_audit([application()], lambda a, b: snapshot(a, b, [], []))
        self.assertIn("身份未确认", result["results"][0]["status"])
        confirmed = run_audit([application()], lambda a, b: snapshot(a, b, [], []), directory=[person(1)])
        self.assertEqual(confirmed["results"][0]["status"], "完整生效区间内未发现VPN流量")

    def test_unknown_coverage_not_unused(self):
        result = run_audit([application()], lambda a, b: snapshot(a, b, [], []), directory=[person(1)], log_start=None)
        self.assertEqual(result["results"][0]["status"], "未发现流量（数据覆盖待确认）")

    def test_unknown_boundary_cannot_certify(self):
        result = run_audit([application()], lambda a, b: snapshot(a, b), server_end="unverified")
        self.assertEqual(result["results"][0]["status"], "返回流量，时间边界待验证")

    def test_partly_observed_validity_not_full_negative(self):
        result = run_audit([application()], lambda a, b: snapshot(a, b, [], []),
                           directory=[person(1)], as_of=stamp("2026-10-02"))
        self.assertEqual(result["results"][0]["status"], "已核查部分未发现流量")
        self.assertFalse(result["results"][0]["full_effective_period_observed"])

    def test_missing_rows_not_empty_rows(self):
        result = run_audit([application()], lambda a, b: {"complete": True, "start": a, "end": b})
        self.assertEqual(result["results"][0]["status"], "查询不完整或失败")

    def test_date_only_end_requires_confirmation(self):
        with self.assertRaises(v.AuditError):
            v.parse_timestamp("2026-10-02", TZ, end=True)

    def test_dst_ambiguous_time_rejected(self):
        with self.assertRaises(v.AuditError):
            v.parse_timestamp("2026-11-01T01:30:00", ZoneInfo("America/New_York"))


class StatisticsTableTests(unittest.TestCase):
    def test_all_vpn_applications_kept_with_flow_and_no_flow(self):
        apps = [application(end="2026-10-01"), application("2026-10-02", "2026-10-02"),
                {**application(), "申请项目": "其他"}]
        def loader(start, end):
            return snapshot(start, end) if start == stamp("2026-10-01") else snapshot(start, end, [], [])
        report = run_audit(apps, loader, directory=[person(1)])
        table = report["statistics_table"]
        self.assertEqual(len(table), 2)
        self.assertEqual([r["姓名"] for r in table], ["测试甲", "测试甲"])
        self.assertEqual([r["申请VPN"] for r in table], ["是", "是"])
        self.assertEqual([r["查询时间范围内是否有流量"] for r in table], ["有", "无"])
        self.assertEqual(table[0]["申请时间"], "2026-09-25")
        self.assertNotEqual(table[0]["本次查询时间范围"], table[0]["实际核查时间范围"])
        self.assertIn("+08:00", table[0]["本次查询时间范围"])
        self.assertEqual(report["statistics_summary"], {"有流量": 1, "无流量": 1, "待确认": 0, "未核查": 0})

    def test_unresolved_absence_not_reported_as_no_flow(self):
        report = run_audit([application()], lambda a, b: snapshot(a, b, [], []))
        self.assertEqual(report["statistics_table"][0]["记录分类"], "待确认")
        self.assertEqual(report["statistics_summary"]["无流量"], 0)
        self.assertIn("身份未确认", report["statistics_table"][0]["查询时间范围内是否有流量"])

    def test_future_and_unverified_boundary_labels_preserved(self):
        report = run_audit([application(), application("2026-12-01", "2026-12-02")],
                           snapshot, server_end="unverified")
        self.assertIn("时间边界待验证", report["statistics_table"][0]["查询时间范围内是否有流量"])
        self.assertEqual(report["statistics_table"][1]["记录分类"], "未核查")
        self.assertEqual(report["statistics_table"][1]["实际核查时间范围"], "")

    def test_offline_cli_exports_required_columns_by_default(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            apps, evidence, output = root / "apps.json", root / "evidence.json", root / "report.json"
            apps.write_text(json.dumps([application()]), encoding="utf-8")
            start, end = stamp("2026-10-01"), stamp("2026-10-02", True) - 1
            evidence.write_text(json.dumps({"snapshots": [snapshot(start, end)]}), encoding="utf-8")
            with patch.object(v.sys, "stdout", io.StringIO()):
                self.assertEqual(v.main(["offline", "--applications", str(apps), "--evidence", str(evidence),
                    "--timezone", "Asia/Shanghai", "--date-end", "inclusive-day", "--window-start", "2026-10-01",
                    "--window-end", "2026-10-31", "--server-end", "inclusive", "--as-of", "2026-11-01",
                    "--output", str(output)]), 0)
            exported = root / "report.csv"
            with exported.open(encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                self.assertEqual(reader.fieldnames[:7], ["姓名", "申请VPN", "申请时间", "申请开始时间", "申请结束时间",
                                                        "本次查询时间范围", "查询时间范围内是否有流量"])
                rows = list(reader)
            self.assertEqual(rows[0]["姓名"], "测试甲")
            self.assertEqual(rows[0]["查询时间范围内是否有流量"], "有")
            self.assertEqual(os.stat(exported).st_mode & 0o777, 0o600)
            saved = json.loads(output.read_text())
            self.assertEqual(saved["statistics_summary"]["有流量"], 1)
            self.assertEqual(len(saved["statistics_table"]), 1)


class EmployeeActivityTests(unittest.TestCase):
    def test_last_seven_days_and_only_requested_employee(self):
        client = v.ConsoleClient()
        stop = stamp("2026-11-13")
        data = snapshot(stop - 7 * 86400, stop, [traffic(1), traffic(2)],
                        [person(1, "示例员工"), person(2, "另一员工")])
        with patch.object(client, "snapshot", return_value=data) as read:
            report = v.employee_activity(client, "示例员工", 7, TZ, stop)
        read.assert_called_once_with(stop - 7 * 86400, stop)
        self.assertEqual(report["results"][0]["employee_id"], "emp_1")
        self.assertEqual(len(report["results"]), 1)
        self.assertEqual(report["results"][0]["total_bytes"], 5)
        self.assertEqual(report["server_end_mode"], "unverified")
        self.assertNotIn("approval_id", report)

    def test_absence_is_not_zero_usage(self):
        client = v.ConsoleClient()
        with patch.object(client, "snapshot", return_value=snapshot(1, 2, [], [])):
            report = v.employee_activity(client, "示例员工", 7, TZ, 1000000)
        self.assertIn("身份未确认", report["status"])
        self.assertEqual(report["results"], [])

    def test_duplicate_names_not_arbitrarily_selected(self):
        client = v.ConsoleClient()
        with patch.object(client, "snapshot", return_value=snapshot(1, 2,
             [traffic(1), traffic(2)], [person(1, "示例员工"), person(2, "示例员工")])):
            report = v.employee_activity(client, "示例员工", 7, TZ, 1000000)
        self.assertEqual(report["status"], "姓名匹配待确认")
        self.assertEqual(report["matched_employee_count"], 2)
        self.assertEqual(report["results"], [])

    def test_incomplete_query_propagates(self):
        client = v.ConsoleClient()
        with patch.object(client, "snapshot", side_effect=v.AuditError("分页不完整")):
            with self.assertRaises(v.AuditError):
                v.employee_activity(client, "示例员工", 7, TZ, 1000000)


class TransportTests(unittest.TestCase):
    def test_check_login_empty_statistics_reminder(self):
        for response in ([], v.EmptyStatistics("员工访问统计返回空值，当前查询期间暂无可读取数据。")):
            output = io.StringIO()
            with self.subTest(response=response), \
                 patch.object(v.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", return_value="synthetic"), \
                 patch.object(v.getpass, "getpass", return_value="synthetic"), \
                 patch.object(v.ConsoleClient, "login", return_value={"confirmed": True}), \
                 patch.object(v.ConsoleClient, "all_stats") as stats, \
                 patch.object(v.sys, "stdout", output):
                if isinstance(response, Exception):
                    stats.side_effect = response
                else:
                    stats.return_value = response
                self.assertEqual(v.main(["check-login", "--account-type", "main"]), 0)
            report = json.loads(output.getvalue().splitlines()[-1])
            self.assertTrue(report["authenticated"])
            self.assertIn("登录成功", report["notice"])
            if isinstance(response, Exception):
                self.assertFalse(report["statistics_readable"])
                self.assertNotIn("sample_employee_count", report)
            else:
                self.assertEqual(report["sample_employee_count"], 0)
                self.assertTrue(report["statistics_readable"])

    def test_check_login_separates_auth_success_from_statistics_failure(self):
        output = io.StringIO()
        with patch.object(v.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="synthetic"), \
             patch.object(v.getpass, "getpass", return_value="synthetic"), \
             patch.object(v.ConsoleClient, "login", return_value={"confirmed": True}), \
             patch.object(v.ConsoleClient, "all_stats", side_effect=v.AuditError("synthetic-error")), \
             patch.object(v.sys, "stdout", output):
            with self.assertRaises(v.AuditError):
                v.main(["check-login", "--account-type", "main"])
        report = json.loads(output.getvalue().splitlines()[-1])
        self.assertTrue(report["authenticated"])
        self.assertTrue(report["instance_confirmed"])
        self.assertFalse(report["statistics_readable"])
        self.assertNotIn("synthetic", output.getvalue())

    def test_invalid_credentials_has_stage_and_environment(self):
        client = v.ConsoleClient("production")
        with patch.object(client, "_request", return_value=b'{"code":1201012,"message":"not echoed"}'):
            with self.assertRaises(v.BusinessError) as caught:
                client._json(client.login_origin + "/api/anon/usercenter/auth/login")
        self.assertEqual(caught.exception.code, 1201012)
        self.assertIn("密码登录", str(caught.exception))
        self.assertIn("production", str(caught.exception))
        self.assertIn("账号/密码错误", str(caught.exception))
        self.assertNotIn("not echoed", str(caught.exception))

    def test_protected_api_failure_not_misreported_as_login(self):
        client = v.ConsoleClient("pre")
        with patch.object(client, "_request", return_value=b'{"code":403}'):
            with self.assertRaises(v.BusinessError) as caught:
                client.business("/openApi/v1/spa")
        self.assertEqual(caught.exception.stage, "获取企业实例")
        self.assertEqual(caught.exception.environment, "pre")

    def test_unknown_error_payload_is_not_echoed(self):
        client = v.ConsoleClient()
        response = json.dumps({"code": "synthetic-private-value", "message": "synthetic-secret"}).encode()
        with patch.object(client, "_request", return_value=response):
            with self.assertRaises(v.BusinessError) as caught:
                client._json(client.login_origin + "/api/anon/usercenter/auth/login")
        self.assertNotIn("synthetic", str(caught.exception))

    def test_bridge_shape_and_encoding(self):
        client = v.ConsoleClient()
        with patch.object(client, "_json", return_value={}) as call:
            client.business(v.STATS, {"page_num": 2, "page_size": 10})
        url, payload = call.call_args.args
        self.assertTrue(url.startswith("https://spa.console.eagleyun.cn/console/v1/request?path="))
        self.assertEqual(payload, {"method": "GET", "path": v.STATS + "?page_num=2&page_size=10", "body": ""})

    def test_external_redirect_blocked(self):
        guard = v.GuardedRedirect({"https://console.eagleyun.cn"})
        request = v.urllib.request.Request("https://console.eagleyun.cn/login")
        with self.assertRaises(v.AuditError):
            guard.redirect_request(request, None, 302, "", {}, "https://example.org/private")

    def test_mfa_stops_before_protected_call(self):
        client = v.ConsoleClient()
        with patch.object(client, "public_key", return_value=b"public"), \
             patch.object(v, "encrypt_rsa", return_value="cipher"), \
             patch.object(client, "_json", side_effect=[{"auth_type": ["password"]}, {"need_mfa_login": True}]), \
             patch.object(client, "select_instance") as select:
            with self.assertRaises(v.AuditError):
                client.login("main", "test", "fake")
            select.assert_not_called()

    def test_main_login_initializes_methods_before_credentials(self):
        client = v.ConsoleClient()
        with patch.object(client, "public_key", return_value=b"public"), \
             patch.object(v, "encrypt_rsa", return_value="synthetic-cipher"), \
             patch.object(client, "_json", side_effect=[{"auth_type": ["password"]}, {}]) as call, \
             patch.object(client, "_request", return_value=b"html"), \
             patch.object(client, "select_instance", return_value={"confirmed": True}):
            self.assertEqual(client.login("main", "synthetic", "synthetic"), {"confirmed": True})
        self.assertIn("/auth/list?account_master=1", call.call_args_list[0].args[0])
        self.assertIn("/auth/login?", call.call_args_list[1].args[0])
        self.assertEqual(call.call_args_list[1].args[1]["account_master"], "1")

    def test_password_not_submitted_if_method_disabled(self):
        client = v.ConsoleClient()
        with patch.object(client, "public_key", return_value=b"public"), \
             patch.object(v, "encrypt_rsa") as encrypt, \
             patch.object(client, "_json", return_value={"auth_type": ["saml"]}) as call:
            with self.assertRaises(v.AuditError):
                client.login("main", "synthetic", "synthetic")
        self.assertEqual(call.call_count, 1)
        encrypt.assert_not_called()

    def test_multi_instance_never_selects_first_arbitrarily(self):
        client = v.ConsoleClient()
        with patch.object(client, "business", return_value=[{"idaas_ins_id": "idaas_a"}, {"idaas_ins_id": "idaas_b"}]):
            with self.assertRaises(v.AuditError):
                client.select_instance()

    def test_explicit_instance_selection(self):
        client = v.ConsoleClient()
        instances = [{"ins_id": "spa_a", "idaas_ins_id": "idaas_a"},
                     {"ins_id": "spa_b", "idaas_ins_id": "idaas_b"}]
        with patch.object(client, "business", return_value=instances):
            self.assertEqual(client.select_instance(ins_id="spa_b")["idaas_ins_id"], "idaas_b")

    def test_rsa_pkcs1_compatibility(self):
        with tempfile.TemporaryDirectory() as folder:
            private, public = Path(folder) / "private.pem", Path(folder) / "public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
            encrypted = v.encrypt_rsa(public.read_bytes(), "synthetic-测试")
            result = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", str(private), "-pkeyopt", "rsa_padding_mode:pkcs1"], input=base64.b64decode(encrypted), capture_output=True, check=True)
            self.assertEqual(result.stdout.decode(), "synthetic-测试")

    def test_private_output_refuses_overwrite_and_csv_formula(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "result.json"
            v.private_json(target, {"a": 1})
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
            with self.assertRaises(v.AuditError):
                v.private_json(target, {"a": 2})
            out = Path(folder) / "result.csv"
            v.private_csv(out, {"results": [{"applicant": "=1+1", "status": "测试"}]})
            self.assertIn("'=1+1", out.read_text(encoding="utf-8-sig"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
