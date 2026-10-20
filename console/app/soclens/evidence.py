"""Evidence Card (§4): alert summary, browser ground truth, user answer, verdict + confidence,
recommended actions, MITRE IDs. Rendered as Markdown (webhooks/Securonix) and HTML (HaloPSA, dashboard)."""
from html import escape

from .models import (CONFIRMED_BY_BROWSER, NO_COVERAGE, NO_RESPONSE, NOT_SEEN_IN_BROWSER, PENDING_USER,
                     USER_CONFIRMED, USER_DENIED, Alert, VerifyRequest)

REPLAY_ACTIONS = [
    "Revoke sessions: Graph `POST /users/{id}/revokeSignInSessions`",
    "Reset the password and re-register MFA if needed",
    "Check inbox rules / forwarding and mailbox delegates",
    "Review OAuth app consents (enterprise apps granted by the user)",
    "Review sign-ins from the alert IP for other users",
]

VERDICT_INFO = {
    CONFIRMED_BY_BROWSER: ("Suggest close as benign / downgrade", "high",
                           ["Close as benign or lower severity (analyst decision - shadow mode)"]),
    USER_CONFIRMED: ("Suggest close with note", "medium",
                     ["Close with note; the user confirmed (users can be wrong or socially engineered)"]),
    NOT_SEEN_IN_BROWSER: ("Escalate P2, start containment review", "high",
                          ["Escalate to P2 and start containment review"] + REPLAY_ACTIONS),
    USER_DENIED: ("P1: revoke sessions, reset password, check inbox rules & OAuth grants", "high",
                  ["Raise to P1 and run the account-compromise playbook"] + REPLAY_ACTIONS),
    NO_RESPONSE: ("Normal analyst triage (user did not answer)", None, ["Continue normal triage; contact the user"]),
    NO_COVERAGE: ("Normal analyst triage (no SOCLens browser for this user)", None,
                  ["Continue normal triage", "Consider deploying SOCLens to this user"]),
    PENDING_USER: ("Waiting for the user's answer", None, ["No action yet - waiting for 'Was this you?'"]),
}

MITRE = {
    "T1078": "Valid Accounts",
    "T1550.004": "Use Alternate Authentication Material: Web Session Cookie",
    "T1528": "Steal Application Access Token",
}


def mitre_for(alert: Alert) -> list[str]:
    ids = ["T1078"]
    if alert.verdict in (NOT_SEEN_IN_BROWSER, USER_DENIED):
        ids += ["T1550.004", "T1528"]
    elif (alert.evidence or {}).get("groundTruth", {}).get("deviceCodeEvents"):
        ids += ["T1528"]
    return ids


def build(alert: Alert, vr: VerifyRequest | None) -> tuple[str, str]:
    verdict = alert.verdict or PENDING_USER
    action, _, actions = VERDICT_INFO.get(verdict, VERDICT_INFO[PENDING_USER])
    ev = alert.evidence or {}
    gt = ev.get("groundTruth", {})
    trace = ev.get("trace", [])
    if gt.get("deviceCodeEvents") and verdict not in (NOT_SEEN_IN_BROWSER, USER_DENIED):
        actions = actions + ["Device-code page was used in the user's browser: check for device-code phishing"]

    summary = [
        ("User", alert.upn), ("Sign-in time", _ts(alert.ts)), ("IP", alert.ip or "-"),
        ("Location", alert.location or "-"), ("App", alert.app or "-"),
        ("Client app", alert.client_app or "Browser (assumed)"), ("IdP", alert.idp),
        ("Source", f"{alert.source} {alert.external_id or ''}".strip()),
        ("Alert", alert.title or "-"),
    ]
    truth = []
    installs = gt.get("installs", [])
    truth.append(("Bound SOCLens browsers", str(len(installs)) if installs else "none"))
    m = gt.get("matchedAuthEvent")
    if m:
        led = m.get("referrerHost") or m.get("openerHost")
        truth.append(("Browser sign-in", f"{m['idp']} {m.get('host') or ''} at {m['ts']} "
                      f"(flow {m.get('flow')}, outcome {m.get('outcome')})"))
        truth.append(("Led there from", led or "direct / unknown"))
    else:
        truth.append(("Browser sign-in", "none matched"))
    ipm = gt.get("ipMatch")
    if ipm:
        truth.append(("IP comparison", f"alert {ipm.get('alertIp')} vs browser {ipm.get('browserIp')}: "
                      f"{ipm.get('kind') or 'no match'}"))
    hb = gt.get("heartbeat")
    if hb:
        truth.append(("Browser online", f"heartbeat {hb['ts']} from {hb['ip']}"))
    for e in gt.get("deviceCodeEvents", [])[:3]:
        truth.append(("Device-code page", f"{e['ts']} from {e.get('referrerHost') or e.get('openerHost') or 'unknown'}"))

    if vr:
        if vr.status == "answered":
            ans = ("Yes, it was me" if vr.answer == "yes" else "No, not me") + f" ({_ts(vr.answered_at)})"
        elif vr.status == "expired":
            ans = f"No answer by {_ts(vr.expires_at)}"
        else:
            ans = f"Asked {_ts(vr.created_at)}, waiting until {_ts(vr.expires_at)}"
    else:
        ans = "Not asked"
    mitre = mitre_for(alert)
    conf = alert.confidence or "n/a"
    limit = ("SOCLens proves *which browser* signed in, not *who* sits at it; malware on the device "
             "(infostealers) still needs EDR.")

    md = [f"### SOCLens Verify: **{verdict}**",
          f"_Suggestion only (shadow mode): SOCLens never closes alerts. Analyst decides._", "",
          f"**Suggested action:** {action}  ", f"**Confidence:** {conf}", "",
          "**Alert**", "", "| | |", "|---|---|"]
    md += [f"| {k} | {_md(v)} |" for k, v in summary]
    md += ["", "**Browser ground truth**", "", "| | |", "|---|---|"]
    md += [f"| {k} | {_md(v)} |" for k, v in truth]
    md += ["", f"**User answer:** {ans}", "", "**How SOCLens decided**", ""]
    md += [f"{i}. {_md(s)}" for i, s in enumerate(trace, 1)]
    md += ["", "**Recommended actions**", ""] + [f"- {a}" for a in actions]
    md += ["", "**MITRE ATT&CK:** " + ", ".join(f"{m} {MITRE[m]}" for m in mitre), "", f"> {limit}"]

    color = {CONFIRMED_BY_BROWSER: "#1a7f37", USER_CONFIRMED: "#1a7f37", NOT_SEEN_IN_BROWSER: "#bf3989",
             USER_DENIED: "#cf222e", NO_RESPONSE: "#9a6700", NO_COVERAGE: "#57606a"}.get(verdict, "#0969da")
    action_items = "".join("<li>" + escape(a.replace("`", "")) + "</li>" for a in actions)
    rows = lambda items: "".join(
        f"<tr><td style='padding:2px 8px;color:#57606a'>{escape(k)}</td><td style='padding:2px 8px'>{escape(str(v))}</td></tr>"
        for k, v in items)
    html = (
        f"<div style='font-family:Segoe UI,Arial,sans-serif;font-size:13px'>"
        f"<div style='border-left:4px solid {color};padding:4px 10px;margin-bottom:8px'>"
        f"<b>SOCLens Verify: <span style='color:{color}'>{escape(verdict)}</span></b><br>"
        f"<i>Suggestion only (shadow mode): SOCLens never closes alerts. Analyst decides.</i><br>"
        f"<b>Suggested action:</b> {escape(action)}<br><b>Confidence:</b> {escape(conf)}</div>"
        f"<b>Alert</b><table>{rows(summary)}</table>"
        f"<b>Browser ground truth</b><table>{rows(truth)}</table>"
        f"<p><b>User answer:</b> {escape(ans)}</p>"
        f"<b>How SOCLens decided</b><ol>{''.join(f'<li>{escape(s)}</li>' for s in trace)}</ol>"
        f"<b>Recommended actions</b><ul>{action_items}</ul>"
        f"<p><b>MITRE ATT&amp;CK:</b> {escape(', '.join(f'{m} {MITRE[m]}' for m in mitre))}</p>"
        f"<p style='color:#57606a'><i>{escape(limit.replace('*', ''))}</i></p></div>")
    return "\n".join(md), html


def _ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "-"


def _md(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")
