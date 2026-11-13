#!/usr/bin/env python3
"""Read-only EagleYun console HTTP client and per-application VPN audit.

Only Python's standard library and the local OpenSSL executable are required.
Passwords are read with getpass; cookies remain in memory for this process.
"""
from __future__ import annotations

import argparse
import base64
import csv
import getpass
import http.cookiejar
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

STATS = "/api/open/das/ztna/analysis/page_l4_access_employee"
ENVIRONMENTS = {
    "production": ("https://console.eagleyun.cn", "https://spa.console.eagleyun.cn"),
    "pre": ("https://console.pre.eagleyun.cn", "https://spa.console.pre.eagleyun.cn"),
}


class AuditError(Exception):
    """A safe, non-secret-bearing error that can be displayed to the operator."""


class EmptyStatistics(AuditError):
    """An explicit null response, without pagination evidence of completeness."""


class BusinessError(AuditError):
    """Only allowlisted labels are shown, never arbitrary server response text."""
    LABELS = {
        1201012: "账号/密码错误",
        1201023: "企业标识不存在",
        1201021: "账号被锁定",
        1201019: "密码登录不可用",
        1202005: "请求受到频率限制或需要验证码",
    }

    def __init__(self, code, environment, stage):
        self.code = code if type(code) is int else None
        self.environment = environment
        self.stage = stage
        label = self.LABELS.get(self.code, "业务请求未成功")
        super().__init__(f"{stage}失败：{label}（环境={environment}，code={self.code if self.code is not None else 'unknown'}）。")


def statistics_shape(data):
    """Describe a failed response without exposing rows, unknown keys or strings."""
    def describe(value):
        if value is None:
            return {"type": "null"}
        if isinstance(value, dict):
            return {"type": "object"}
        if isinstance(value, list):
            return {"type": "array", "length": len(value)}
        return {"type": "boolean" if isinstance(value, bool) else
                "number" if isinstance(value, (int, float)) else "string"}

    def fields(value, nested=True):
        result = describe(value)
        if not isinstance(value, dict):
            return result
        allowed = ("rows", "page_info", "data", "list", "items", "records", "result")
        result["fields"] = {key: describe(value[key]) for key in allowed if key in value}
        result["other_field_count"] = sum(key not in allowed for key in value)
        info = value.get("page_info")
        if isinstance(info, dict):
            for key in ("current_page", "page_size", "total_num"):
                number = info.get(key)
                if type(number) is int and 0 <= number <= 1000000:
                    result["fields"]["page_info"][key] = number
        if nested and "data" in value:
            result["fields"]["data"] = fields(value["data"], nested=False)
        return result

    return json.dumps(fields(data), ensure_ascii=False, separators=(",", ":"))


class GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origins):
        self.origins = set(origins)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        if u.username or u.password or f"{u.scheme}://{u.netloc}" not in self.origins:
            raise AuditError("服务重定向到所选环境以外的地址，已停止。")
        if req.get_method() != "GET" and code in (307, 308):
            raise AuditError("凭据请求发生保留请求体的重定向，已停止。")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def encrypt_rsa(pem, value):
    openssl = shutil.which("openssl")
    if not openssl:
        raise AuditError("未找到 OpenSSL；请使用带有 OpenSSL 的 Python 运行环境。")
    # The temporary file contains only the PUBLIC key. Credentials go through stdin.
    with tempfile.TemporaryDirectory(prefix="eagleyun-public-key-") as folder:
        public = Path(folder) / "public.pem"
        public.write_bytes(pem)
        result = subprocess.run(
            [openssl, "pkeyutl", "-encrypt", "-pubin", "-inkey", str(public),
             "-pkeyopt", "rsa_padding_mode:pkcs1"],
            input=value.encode("utf-8"), capture_output=True, check=False,
        )
    if result.returncode:
        raise AuditError("凭据 RSA 加密失败；检查公钥格式或输入长度。")
    return base64.b64encode(result.stdout).decode("ascii")


class ConsoleClient:
    def __init__(self, environment="production", timeout=30):
        self.environment = environment
        self.login_origin, self.api_origin = ENVIRONMENTS[environment]
        self.origins = {self.login_origin, self.api_origin}
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), GuardedRedirect(self.origins)
        )
        self.timeout = timeout
        self.instance = None
        self.identity_cache = {}

    def _request(self, url, payload=None):
        u = urllib.parse.urlsplit(url)
        if u.username or u.password or f"{u.scheme}://{u.netloc}" not in self.origins:
            raise AuditError("请求地址不属于所选亿格云环境。")
        headers = {"Accept": "application/json, text/html", "User-Agent": "EagleYun-VPN-Audit/1"}
        if payload is not None:
            headers.update({"Content-Type": "application/json", "Origin": self.api_origin
                            if url.startswith(self.api_origin + "/") else self.login_origin})
            # Select the CSRF cookie using CookieJar's domain/path rules for this URL.
            probe = urllib.request.Request(url)
            self.jar.add_cookie_header(probe)
            cookie = probe.get_header("Cookie", "")
            match = re.search(r"(?:^|;\s*)csrf=([^;]*)", cookie)
            if match:
                headers["X-CSRF-TOKEN"] = urllib.parse.unquote(match.group(1))
        data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            raise AuditError(f"HTTP 请求失败（状态 {exc.code}）；未把错误响应当作空数据。") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise AuditError("网络请求失败或超时；请检查网络，未自动重试凭据。") from None
        if len(raw) > 32 * 1024 * 1024:
            raise AuditError("响应超过大小限制，未将截断响应作为完整数据。")
        return raw

    def _json(self, url, payload=None):
        raw = self._request(url, payload)
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise AuditError("接口没有返回 JSON，可能已重定向至登录页。") from None
        if not isinstance(result, dict) or result.get("code") != 200:
            code = result.get("code") if isinstance(result, dict) else "unknown"
            path = urllib.parse.urlsplit(url).path
            stage = {"/api/anon/usercenter/auth/login": "密码登录",
                     "/api/anon/usercenter/auth/list": "账号类型/企业校验"}.get(path, "接口查询")
            if path == "/console/v1/request":
                internal = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get("path", [""])[0]
                stage = {"/openApi/v1/spa": "获取企业实例", STATS: "员工访问统计"}.get(internal, "业务接口查询")
            raise BusinessError(code, self.environment, stage)
        return result.get("data")

    def public_key(self):
        raw = self._request(self.login_origin + "/login").decode("utf-8")
        match = re.search(r"\bPUBLIC_KEY\s*:\s*['\"]([A-Za-z0-9+/=\s]+)['\"]", raw)
        if not match:
            raise AuditError("登录 HTML 中未找到 PUBLIC_KEY，不能继续猜测加密参数。")
        try:
            pem = base64.b64decode(match.group(1), validate=False)
        except ValueError:
            raise AuditError("登录公钥格式不正确。") from None
        if not pem.startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise AuditError("登录公钥不是预期的 PEM 公钥。")
        return pem

    def login(self, account_type, account, password, corp_code=None, agreement_accepted=False, ins_id=None):
        pem = self.public_key()  # Establish cookies before submitting credentials.
        if account_type not in ("main", "sub") or not account.strip() or not password:
            raise AuditError("账号类型、账号或密码未提供。")
        if account_type == "sub" and not corp_code:
            raise AuditError("独立子账号登录需要已确认的企业上下文，请提供企业标识码。")
        method_query = {"account_master": "1" if account_type == "main" else "0"}
        if account_type == "sub":
            method_query["corp_code"] = corp_code
        query = urllib.parse.urlencode(method_query)
        methods = self._json(self.login_origin + "/api/anon/usercenter/auth/list?" + query)
        if not isinstance(methods, dict) or not isinstance(methods.get("auth_type"), list):
            raise AuditError("登录方法响应结构变化，未提交账号密码。")
        if "password" not in methods["auth_type"]:
            raise AuditError("所选账号类型/企业未提供密码登录，未提交账号密码。")
        payload = {"account_master": "1" if account_type == "main" else "0",
                   "login_name": encrypt_rsa(pem, account.strip()),
                   "password": encrypt_rsa(pem, password)}
        if corp_code:
            payload["corp_code"] = corp_code
        if agreement_accepted:
            payload["agreement_accepted"] = 1
        query = urllib.parse.urlencode({"redirect": self.api_origin + "/"})
        state = self._json(self.login_origin + "/api/anon/usercenter/auth/login?" + query, payload)
        if not isinstance(state, dict):
            raise AuditError("登录响应结构变化，不能确认登录状态。")
        if state.get("need_mfa_login"):
            raise AuditError("账号需要 MFA；当前脚本未实现 MFA，已停止，未改为打开网页。")
        if state.get("need_force_reset_pwd") or state.get("password_expire") == -1:
            raise AuditError("账号要求重置密码或密码已过期，请用户自行处理。")
        target = state.get("redirect_url") or self.api_origin + "/"
        self._request(urllib.parse.urljoin(self.login_origin, target))
        # Success is established by a protected API call, not the login HTTP status.
        return self.select_instance(corp_code=corp_code, ins_id=ins_id)

    def business(self, path, query=None):
        if not path.startswith(("/api/open/", "/openApi/")) or "?" in path:
            raise AuditError("业务接口路径不符合已捕获的请求结构。")
        internal = path + ("?" + urllib.parse.urlencode(query, doseq=True) if query else "")
        url = self.api_origin + "/console/v1/request?" + urllib.parse.urlencode({"path": path})
        return self._json(url, {"method": "GET", "path": internal, "body": ""})

    def select_instance(self, corp_code=None, ins_id=None):
        instances = self.business("/openApi/v1/spa")
        if not isinstance(instances, list) or not all(isinstance(x, dict) for x in instances):
            raise AuditError("企业实例列表结构变化。")
        choices = instances
        if corp_code:
            choices = [x for x in choices if x.get("corp_code") == corp_code]
        if ins_id:
            choices = [x for x in choices if x.get("ins_id") == ins_id]
        if len(choices) != 1:
            raise AuditError("未能唯一确定目标企业实例；请指定企业标识码或实例 ID。")
        instance = choices[0]
        if not re.fullmatch(r"idaas_[A-Za-z0-9-]+", str(instance.get("idaas_ins_id", ""))):
            raise AuditError("当前企业缺少有效的 idaas_ins_id。")
        if instance.get("private_model"):
            raise AuditError("当前实例需要私有模块路由，本脚本尚未验证该路由。")
        self.instance = instance
        return instance

    def all_stats(self, start, end):
        if not isinstance(start, int) or not isinstance(end, int) or end < start:
            raise AuditError("查询时间必须为有效的 Unix 秒。")
        page, expected_total, seen, rows = 1, None, set(), []
        while True:
            data = self.business(STATS, {
                "sort_list": json.dumps([{"sort_field": "total_bytes", "sort_type": "desc"}], separators=(",", ":")),
                "start_time": start, "end_time": end, "page_num": page, "page_size": 10,
            })
            if data is None or (isinstance(data, dict) and "rows" in data
                                and data["rows"] is None and data.get("page_info") is None):
                if page != 1:
                    raise AuditError("员工统计分页中途返回空值，查询不完整，不能视为暂无数据。")
                raise EmptyStatistics("员工访问统计返回空值，当前查询期间暂无可读取数据；不能据此判定员工未使用 VPN。")
            if (isinstance(data, dict) and "rows" in data and data["rows"] is None
                    and isinstance(data.get("page_info"), dict)
                    and type(data["page_info"].get("total_num")) is int
                    and data["page_info"]["total_num"] == 0):
                # A null rows slice is empty only with explicit zero-total metadata.
                data = {**data, "rows": []}
            if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
                raise AuditError("员工统计响应结构不正确；结构诊断=" + statistics_shape(data))
            info, batch = data.get("page_info"), data["rows"]
            if not isinstance(info, dict):
                raise AuditError("响应缺少分页元数据；结构诊断=" + statistics_shape(data))
            current, size, total = (info.get(x) for x in ("current_page", "page_size", "total_num"))
            if (type(current) is not int or type(size) is not int or type(total) is not int
                    or current != page or size != 10 or total < 0):
                raise AuditError("响应页码、每页数量或总数不符合请求。")
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise AuditError("取数期间总记录数变化，不能证明分页完整。")
            if total > 1000000:
                raise AuditError("记录数超过当前客户端取数上限。")
            expected_size = min(size, max(0, total - (page - 1) * size))
            if len(batch) != expected_size:
                raise AuditError("出现提前空页、短页或超量页，查询不完整。")
            for row in batch:
                if not isinstance(row, dict) or not row.get("employee_id"):
                    raise AuditError("统计记录缺少员工 ID。")
                identity = row["employee_id"]
                if not isinstance(identity, str) or identity in seen:
                    raise AuditError("分页出现重复或无效员工 ID，查询不完整。")
                for field in ("access_count", "request_bytes", "response_bytes", "total_bytes"):
                    if type(row.get(field)) is not int or row[field] < 0:
                        raise AuditError("流量或次数字段缺失、非整数或为负，不能当作零。")
                if row["total_bytes"] != row["request_bytes"] + row["response_bytes"]:
                    raise AuditError("请求、响应和总流量未能核对。")
                seen.add(identity)
                rows.append(dict(row))
            if len(rows) == total:
                return rows
            page += 1

    def employee(self, employee_id):
        if employee_id in self.identity_cache:
            return self.identity_cache[employee_id]
        if not self.instance:
            raise AuditError("请先确认企业实例。")
        ins = self.instance["idaas_ins_id"]
        data = self.business(f"/openApi/v1/idaas/{ins}/search/getNameById", {
            "match_type": "employee", "ids": employee_id, "query_deleted": "true",
        })
        if not isinstance(data, list):
            raise AuditError("员工身份响应结构不正确。")
        matches = [x for x in data if isinstance(x, dict) and x.get("id") == employee_id
                   and x.get("match_type") == "employee"]
        if len(matches) != 1:
            raise AuditError("员工身份未返回唯一对应记录。")
        self.identity_cache[employee_id] = dict(matches[0])
        return self.identity_cache[employee_id]

    def snapshot(self, start, end):
        rows = self.all_stats(start, end)
        # Identity errors invalidate this snapshot; never silently drop a row.
        employees = [self.employee(row["employee_id"]) for row in rows]
        return {"start": start, "end": end, "complete": True, "rows": rows, "employees": employees}


def read_records(path):
    path = Path(path)
    if path.suffix.lower() == ".json":
        records = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
            raise AuditError("JSON 申请表必须是对象数组。")
        return records
    if path.suffix.lower() not in (".csv", ".tsv"):
        raise AuditError("请先将工作表或 MCP 结果提取为 CSV、TSV 或 JSON 对象数组。")
    text = path.read_text(encoding="utf-8-sig")
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    return list(csv.DictReader(io.StringIO(text), delimiter=delimiter))


def field(row, *names):
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return value
    return ""


def parse_timestamp(value, tz, end=False, date_end=None):
    if not isinstance(value, str):
        raise AuditError("时间字段必须是日期或 ISO 日期时间字符串。")
    value = value.strip()
    date_only = bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value))
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AuditError("时间格式错误，请使用 YYYY-MM-DD 或 ISO 日期时间。") from None
    if date_only and end:
        if date_end not in ("inclusive-day", "exclusive-day"):
            raise AuditError("结束时间仅有日期，必须确认是否包含结束日期全天。")
        if date_end == "inclusive-day":
            parsed += timedelta(days=1)
    if parsed.tzinfo is None:
        # Reject nonexistent/ambiguous local wall times rather than guessing at DST.
        first = parsed.replace(tzinfo=tz, fold=0)
        second = parsed.replace(tzinfo=tz, fold=1)
        if first.utcoffset() != second.utcoffset():
            raise AuditError("本地时间处于夏令时转换区间，请提供明确 UTC 偏移。")
        parsed = first
    if parsed.microsecond:
        raise AuditError("统计接口使用秒级时间，请提供整秒时间。")
    return int(parsed.timestamp())


def vpn_project(value):
    if isinstance(value, list):
        return any(str(x).strip().upper() == "VPN" for x in value)
    return "VPN" in [x.strip().upper() for x in re.split(r"[,，;；|、]", str(value))]


def build_audit(records, snapshot_loader, *, tz, date_end, window_start, window_end,
                as_of, server_end="unverified", scope_confirmed=False, log_start=None,
                directory=None):
    """Compare each VPN approval against its own effective interval.

    All in-memory intervals use an exclusive end. For exact timestamps, that end
    is the timestamp supplied; for date-only ends, date_end controls conversion.
    """
    cache, results = {}, []
    directory = directory or []
    if not all(isinstance(x, dict) and x.get("id") for x in directory):
        raise AuditError("员工目录必须包含有 id 字段的员工对象。")
    for index, record in enumerate(records, 1):
        if not vpn_project(field(record, "申请项目", "project")):
            continue
        name = str(field(record, "申请人", "applicant")).strip()
        out = {"source_row": index, "approval_id": field(record, "审批编号", "approval_id"),
               "applicant": name, "department": field(record, "申请人·部门", "申请人部门", "department"),
               "applied_at": field(record, "申请时间", "applied_at"),
               "effective_start": field(record, "生效开始时间", "生效开始", "effective_start"),
               "effective_end": field(record, "生效结束时间", "生效结束", "effective_end"),
               "approval_status": field(record, "审批状态", "approval_status"),
               "account_status": field(record, "账号权限状态", "account_status"),
               "status": None, "notes": []}
        results.append(out)
        try:
            if not name:
                raise AuditError("申请人姓名缺失。")
            begin = parse_timestamp(out["effective_start"], tz)
            finish = parse_timestamp(out["effective_end"], tz, end=True, date_end=date_end)
            if finish <= begin:
                raise AuditError("生效结束必须晚于生效开始。")
        except AuditError as exc:
            out.update(status="申请字段异常", notes=[str(exc)])
            continue
        start, stop = max(begin, window_start), min(finish, window_end, as_of)
        out["full_effective_period_observed"] = start == begin and stop == finish
        if begin >= as_of:
            out["status"] = "尚未生效"
            continue
        if min(finish, window_end) <= max(begin, window_start):
            out["status"] = "不在指定查询范围"
            continue
        if stop <= start:
            out["status"] = "查询范围尚未发生"
            continue
        out.update(query_start=start, query_end_exclusive=stop, server_end_mode=server_end)
        if not out["full_effective_period_observed"]:
            out["notes"].append("仅核查已发生且与指定范围重叠的部分，不能推断剩余有效期。")
        request_end = stop - 1 if server_end == "inclusive" else stop
        key = start, request_end
        if key not in cache:
            try:
                snapshot = snapshot_loader(*key)
                if not isinstance(snapshot, dict) or snapshot.get("complete") is not True:
                    raise AuditError("未取得完整分页数据。")
                if not isinstance(snapshot.get("rows"), list) or not isinstance(snapshot.get("employees"), list):
                    raise AuditError("证据缺少明确的 rows 或 employees 数组。")
                ids = []
                for item in snapshot["rows"]:
                    if not isinstance(item, dict) or not isinstance(item.get("employee_id"), str):
                        raise AuditError("证据存在缺少员工 ID 的流量记录。")
                    ids.append(item["employee_id"])
                    if any(type(item.get(f)) is not int or item[f] < 0 for f in (
                            "access_count", "request_bytes", "response_bytes", "total_bytes")):
                        raise AuditError("证据中的流量或次数字段缺失或不合法。")
                    if item["total_bytes"] != item["request_bytes"] + item["response_bytes"]:
                        raise AuditError("证据中的流量合计未能核对。")
                if len(set(ids)) != len(ids):
                    raise AuditError("证据中存在重复员工 ID。")
                if snapshot.get("start") != start or snapshot.get("end") != request_end:
                    raise AuditError("流量证据的时间范围与本次申请不符。")
                cache[key] = snapshot
            except AuditError as exc:
                cache[key] = exc
        evidence = cache[key]
        if isinstance(evidence, AuditError):
            out.update(status="查询不完整或失败", notes=out["notes"] + [str(evidence)])
            continue
        people = {p["id"]: p for p in directory}
        for person in evidence.get("employees", []):
            if isinstance(person, dict) and person.get("id"):
                people[person["id"]] = person
        explicit_id = str(field(record, "员工ID", "employee_id")).strip()
        if explicit_id:
            matches = [p for p in people.values() if p["id"] == explicit_id]
        else:
            matches = [p for p in people.values() if str(p.get("name", "")).strip() == name]
        if len(matches) != 1:
            out["status"] = "姓名匹配待确认" if len(matches) > 1 else "未发现同名流量记录（身份未确认）"
            out["notes"].append("活跃员工列表无法证明未出现的申请人属于本企业；可提供独立员工目录核实。")
            continue
        person = matches[0]
        identity = person["id"]
        out.update(employee_id=identity, match_method="employee_id" if explicit_id else "unique_name",
                   employee_name=person.get("name"), employee_login_name=person.get("employee_login_name", ""))
        matching_rows = [r for r in evidence.get("rows", []) if r.get("employee_id") == identity]
        if len(matching_rows) > 1:
            out["status"] = "查询不完整或失败"
            out["notes"].append("同一统计区间出现重复员工记录。")
            continue
        row = matching_rows[0] if matching_rows else {x: 0 for x in (
            "access_count", "total_bytes", "request_bytes", "response_bytes")}
        if any(type(row.get(x)) is not int or row[x] < 0 for x in (
                "access_count", "total_bytes", "request_bytes", "response_bytes")):
            out["status"] = "查询不完整或失败"
            out["notes"].append("流量或次数缺失，不将其视为零。")
            continue
        out.update({x: row[x] for x in ("access_count", "total_bytes", "request_bytes", "response_bytes")})
        if server_end == "unverified":
            out["status"] = "返回流量，时间边界待验证" if row["total_bytes"] > 0 else "未发现流量，时间边界待验证"
        elif row["total_bytes"] > 0:
            out["status"] = "核查区间内使用过VPN"
        elif not scope_confirmed or log_start is None or log_start > start:
            out["status"] = "未发现流量（数据覆盖待确认）"
            out["notes"].append("需要确认账号可见范围及日志留存覆盖查询期间，才能给出完整结论。")
        elif not out["full_effective_period_observed"]:
            out["status"] = "已核查部分未发现流量"
        else:
            out["status"] = "完整生效区间内未发现VPN流量"
    report = {"window_start": window_start, "window_end_exclusive": window_end, "as_of": as_of,
            "timezone": str(tz), "date_end": date_end, "server_end_mode": server_end,
            "scope_confirmed": scope_confirmed, "log_start": log_start,
            "vpn_application_count": len(results), "queried_interval_count": len(cache), "results": results}
    report["statistics_table"] = audit_table_rows(report)
    report["statistics_summary"] = {group: sum(row["记录分类"] == group for row in report["statistics_table"])
                                    for group in ("有流量", "无流量", "待确认", "未核查")}
    return report


AUDIT_TABLE_COLUMNS = ["姓名", "申请VPN", "申请时间", "申请开始时间", "申请结束时间",
                       "本次查询时间范围", "查询时间范围内是否有流量", "实际核查时间范围",
                       "记录分类", "访问次数", "总流量_字节", "请求流量_字节", "响应流量_字节",
                       "审批编号", "员工ID", "源记录行号", "核查结果", "说明"]


def audit_table_rows(report):
    """One display row per VPN application, including zero-use and unresolved rows."""
    tz = ZoneInfo(report.get("timezone", "UTC"))
    def interval(start, stop):
        if type(start) is not int or type(stop) is not int:
            return ""
        return (datetime.fromtimestamp(start, tz).isoformat() + " 至 "
                + datetime.fromtimestamp(stop, tz).isoformat() + "（结束时刻不含）")
    window = interval(report.get("window_start"), report.get("window_end_exclusive"))
    rows = []
    for result in report["results"]:
        status = result.get("status", "")
        if status == "核查区间内使用过VPN":
            group, flow = "有流量", "有"
        elif status == "返回流量，时间边界待验证":
            group, flow = "有流量", "有（时间边界待验证）"
        elif status == "完整生效区间内未发现VPN流量":
            group, flow = "无流量", "无"
        elif status == "已核查部分未发现流量":
            group, flow = "无流量", "已核查部分无（未覆盖完整申请有效期）"
        elif status in ("尚未生效", "不在指定查询范围", "查询范围尚未发生", "申请字段异常"):
            group, flow = "未核查", "未核查（" + status + "）"
        else:
            group, flow = "待确认", "待确认（" + (status or "结果缺失") + "）"
        row = {"姓名": result.get("applicant", ""), "申请VPN": "是",
               "申请时间": result.get("applied_at", ""),
               "申请开始时间": result.get("effective_start", ""),
               "申请结束时间": result.get("effective_end", ""),
               "本次查询时间范围": window, "查询时间范围内是否有流量": flow,
               "实际核查时间范围": interval(result.get("query_start"), result.get("query_end_exclusive")),
               "记录分类": group, "审批编号": result.get("approval_id", ""),
               "员工ID": result.get("employee_id", ""), "源记录行号": result.get("source_row", ""),
               "核查结果": status, "说明": result.get("notes", [])}
        row.update({label: result.get(key, "") for key, label in (
            ("access_count", "访问次数"), ("total_bytes", "总流量_字节"),
            ("request_bytes", "请求流量_字节"), ("response_bytes", "响应流量_字节"))})
        rows.append(row)
    return rows


def employee_activity(client, name, days, tz, as_of=None):
    """Read one employee's activity without inventing an approval or validity period."""
    if not name.strip() or type(days) is not int or days <= 0:
        raise AuditError("请提供员工姓名和正整数查询天数。")
    stop = int(datetime.now(timezone.utc).timestamp()) if as_of is None else as_of
    start = stop - days * 86400
    evidence = client.snapshot(start, stop)
    matches = [p for p in evidence["employees"] if str(p.get("name", "")).strip() == name.strip()]
    report = {"mode": "employee-activity", "environment": client.environment,
              "employee_name_query": name.strip(), "timezone": str(tz),
              "window_start": start, "window_end": stop,
              "window_start_local": datetime.fromtimestamp(start, tz).isoformat(),
              "window_end_local": datetime.fromtimestamp(stop, tz).isoformat(),
              "last_days": days, "server_end_mode": "unverified",
              "pagination_complete": True, "matched_employee_count": len(matches),
              "results": [], "notes": ["服务端时间端点包含规则尚未验证；本次不进行申请有效期比对。"]}
    if len(matches) != 1:
        report["status"] = "姓名匹配待确认" if matches else "未发现同名流量记录（身份未确认）"
        report["notes"].append("活跃清单没有唯一同名记录，不能据此判定该员工未使用 VPN。")
        return report
    person = matches[0]
    rows = [row for row in evidence["rows"] if row["employee_id"] == person["id"]]
    if len(rows) != 1:
        raise AuditError("员工身份与统计记录未能唯一关联。")
    row = rows[0]
    report["status"] = "返回流量，时间边界待验证" if row["total_bytes"] > 0 else "未发现流量，时间边界待验证"
    report["results"] = [{"employee_id": person["id"], "employee_name": person.get("name"),
                          "employee_login_name": person.get("employee_login_name", ""),
                          "department": person.get("department", []), **{key: row[key] for key in
                          ("access_count", "total_bytes", "request_bytes", "response_bytes")}}]
    return report


def private_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise AuditError("输出文件已存在，请更换输出路径。") from None
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def private_csv(path, report):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise AuditError("CSV 输出已存在，请更换输出路径。") from None
    def cell(value):
        if isinstance(value, list):
            value = "；".join(str(x) for x in value)
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + value
        return value
    with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(AUDIT_TABLE_COLUMNS)
        for row in audit_table_rows(report):
            writer.writerow([cell(row.get(key, "")) for key in AUDIT_TABLE_COLUMNS])


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("inspect-login", "check-login", "audit", "offline", "employee-activity"))
    p.add_argument("--environment", choices=ENVIRONMENTS, default="production")
    p.add_argument("--account-type", choices=("main", "sub"))
    p.add_argument("--corp-code")
    p.add_argument("--ins-id", help="仅在已确认目标且账号拥有多个实例时指定")
    p.add_argument("--agreement-accepted", action="store_true", help="仅在用户已明确接受协议后使用")
    p.add_argument("--applications")
    p.add_argument("--employee-name", help="直接查询员工流量，不进行申请表比对")
    p.add_argument("--last-days", type=int, help="从执行查询时刻回溯的完整 24 小时天数")
    p.add_argument("--evidence", help="离线证据 JSON：snapshots 数组，每项含 start/end/complete/rows/employees")
    p.add_argument("--employee-directory", help="独立完整员工目录的 JSON 对象数组，可用于核实无流量员工")
    p.add_argument("--timezone", help="用户确认的 IANA 时区，例如 Asia/Shanghai")
    p.add_argument("--date-end", choices=("inclusive-day", "exclusive-day"))
    p.add_argument("--window-start")
    p.add_argument("--window-end", help="日期时间表示排他结束；仅日期时受 --date-end 控制")
    p.add_argument("--as-of", help="核查截止时刻；缺省为执行时刻，不能晚于真实当前时间")
    p.add_argument("--server-end", choices=("inclusive", "exclusive", "unverified"), default="unverified",
                   help="服务端 end_time 语义，须按接口证据设置；业务日期确认不能代替接口验证")
    p.add_argument("--scope-confirmed", action="store_true")
    p.add_argument("--log-start", help="已经确认的最早可查询日志时间，未知则不作完整未使用结论")
    p.add_argument("--output", help="输出 JSON 文件，默认拒绝覆盖，权限 0600")
    p.add_argument("--csv-output", help="中文统计表路径；申请核查默认保存为与 JSON 同名的 .csv")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "employee-activity":
        if not args.employee_name or not args.employee_name.strip() or not args.last_days or args.last_days < 1 or not args.timezone:
            raise AuditError("直接查询员工需提供 --employee-name、--last-days 正整数和 --timezone。")
        tz = ZoneInfo(args.timezone)
        if args.output and Path(args.output).exists():
            raise AuditError("输出文件已存在，请更换路径。")
        if args.applications or args.csv_output or args.window_start or args.window_end or args.as_of:
            raise AuditError("直接员工查询仅使用 --last-days，不接收申请表、绝对时间或申请核查 CSV 参数。")
    if args.command == "inspect-login":
        client = ConsoleClient(args.environment)
        pem = client.public_key()
        print(json.dumps({"environment": args.environment, "public_key_found": bool(pem),
                          "openssl_available": bool(shutil.which("openssl")), "authenticated": False}))
        return 0
    if args.command in ("audit", "offline"):
        required = ("applications", "timezone", "date_end", "window_start", "window_end", "output")
        if any(not getattr(args, key) for key in required):
            raise AuditError("核查需提供申请表、时区、结束日期规则、查询起止时间和输出路径。")
        if not args.csv_output:
            args.csv_output = str(Path(args.output).with_suffix(".csv"))
        if Path(args.output).exists() or (args.csv_output and Path(args.csv_output).exists()):
            raise AuditError("输出文件已存在，请更换路径。")
        if args.csv_output and Path(args.output).resolve() == Path(args.csv_output).resolve():
            raise AuditError("JSON 和 CSV 输出路径必须不同。")
        tz = ZoneInfo(args.timezone)
        window_start = parse_timestamp(args.window_start, tz)
        window_end = parse_timestamp(args.window_end, tz, end=True, date_end=args.date_end)
        if window_end <= window_start:
            raise AuditError("查询结束必须晚于查询开始。")
        now = int(datetime.now(timezone.utc).timestamp())
        as_of = parse_timestamp(args.as_of, tz) if args.as_of else now
        if args.command == "audit" and as_of > now:
            raise AuditError("在线核查截止时刻不能晚于当前时间。")
        log_start = parse_timestamp(args.log_start, tz) if args.log_start else None
        records = read_records(args.applications)
        directory = read_records(args.employee_directory) if args.employee_directory else []
        if args.command == "offline":
            if not args.evidence:
                raise AuditError("离线核查需提供 --evidence。")
            data = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
            snapshots = data.get("snapshots", [])
            def loader(start, end):
                found = [x for x in snapshots if x.get("start") == start and x.get("end") == end]
                if len(found) != 1:
                    raise AuditError("离线证据没有唯一对应的查询区间。")
                return found[0]
        else:
            loader = None
    if args.command in ("check-login", "audit", "employee-activity"):
        if not sys.stdin.isatty():
            raise AuditError("凭据必须在交互终端中输入，不从脚本参数或普通管道接收。")
        print(f"目标环境：{args.environment}；登录地址：{ENVIRONMENTS[args.environment][0]}")
        if not args.account_type:
            choice = input("账号类型：主账号填 main，子账号填 sub： ").strip()
            if choice not in ("main", "sub"):
                raise AuditError("账号类型必须为 main 或 sub。")
            args.account_type = choice
        if args.account_type == "sub" and not args.corp_code:
            args.corp_code = input("企业标识码（独立 HTTP 会话没有浏览器中的企业上下文）： ").strip()
            if not args.corp_code:
                raise AuditError("缺少企业标识码，无法开始独立子账号鉴权。")
        account = input("亿格云账号（仅发送到所选环境）： ").strip()
        password = getpass.getpass("亿格云密码（隐藏输入、不保存）： ")
        client = ConsoleClient(args.environment)
        try:
            instance = client.login(args.account_type, account, password, args.corp_code,
                                    args.agreement_accepted, ins_id=args.ins_id)
        finally:
            password = ""
        if args.command == "employee-activity":
            try:
                report = employee_activity(client, args.employee_name, args.last_days, tz)
            except EmptyStatistics as exc:
                print("登录成功。" + str(exc), flush=True)
                raise
            if args.output:
                private_json(args.output, report)
                print("查询结果已保存：" + str(Path(args.output).resolve()))
            print(json.dumps(report, ensure_ascii=False))
            return 0
        if args.command == "check-login":
            # Exercise the actual statistics endpoint, not just instance discovery.
            now = int(datetime.now(timezone.utc).timestamp())
            try:
                rows = client.all_stats(now - 86400, now)
            except EmptyStatistics as exc:
                report = {"environment": args.environment, "authenticated": True,
                          "instance_confirmed": bool(instance), "statistics_readable": False,
                          "statistics_status": "empty_response", "sample_window_seconds": 86400,
                          "notice": "登录成功。" + str(exc)}
                if args.output:
                    private_json(args.output, report)
                print(json.dumps(report, ensure_ascii=False))
                return 0
            except AuditError:
                print(json.dumps({"environment": args.environment, "authenticated": True,
                                  "instance_confirmed": bool(instance), "statistics_readable": False},
                                 ensure_ascii=False), flush=True)
                raise
            report = {"environment": args.environment, "authenticated": True,
                      "instance_confirmed": bool(instance), "statistics_readable": True,
                      "sample_window_seconds": 86400, "sample_employee_count": len(rows)}
            if not rows:
                report["statistics_status"] = "empty_confirmed"
                report["notice"] = "登录成功。过去 24 小时员工访问统计暂无数据（总记录数为 0），不代表所有申请有效期内均未使用 VPN。"
            if args.output:
                private_json(args.output, report)
            print(json.dumps(report, ensure_ascii=False))
            return 0
        loader = client.snapshot
    report = build_audit(records, loader, tz=tz, date_end=args.date_end,
                         window_start=window_start, window_end=window_end, as_of=as_of,
                         server_end=args.server_end, scope_confirmed=args.scope_confirmed,
                         log_start=log_start, directory=directory)
    report["mode"] = args.command
    report["environment"] = args.environment if args.command == "audit" else "offline"
    private_json(args.output, report)
    if args.csv_output:
        private_csv(args.csv_output, report)
    print(json.dumps({"saved": str(Path(args.output).resolve()),
                      "csv_saved": str(Path(args.csv_output).resolve()) if args.csv_output else None,
                      "vpn_application_count": report["vpn_application_count"],
                      "queried_interval_count": report["queried_interval_count"],
                      "statistics_summary": report["statistics_summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AuditError, ValueError, OSError, KeyError) as exc:
        # Unexpected I/O errors can contain paths; never dump request payloads or cookies.
        message = str(exc) if isinstance(exc, AuditError) else "输入、文件或运行环境异常，请检查配置。"
        print("未完成：" + message, file=sys.stderr)
        sys.exit(2)
