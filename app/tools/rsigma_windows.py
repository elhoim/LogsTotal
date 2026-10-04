"""Windows event aliases and logsource restrictions for RSigma's batch evaluator.

Pure stdlib; also used by the tool updater to stage its matching pipeline.
The event body is retained when aliases are added. Channel + EventID is a single
condition so Sysmon/1 and Security/4688 do not become a Cartesian product.
"""

from __future__ import annotations

import json

SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
PROVIDERS = {
    SYSMON: "Microsoft-Windows-Sysmon",
    "Security": "Microsoft-Windows-Security-Auditing",
    POWERSHELL: "Microsoft-Windows-PowerShell",
    "PowerShellCore/Operational": "PowerShellCore",
    "Windows PowerShell": "PowerShell",
}
CATEGORIES = {
    "process_creation": [(SYSMON, 1), ("Security", 4688)],
    "file_change": [(SYSMON, 2)],
    "network_connection": [(SYSMON, 3)],
    "sysmon_status": [(SYSMON, 4), (SYSMON, 16)],
    "process_termination": [(SYSMON, 5)],
    "driver_load": [(SYSMON, 6)],
    "image_load": [(SYSMON, 7)],
    "create_remote_thread": [(SYSMON, 8)],
    "raw_access_thread": [(SYSMON, 9)],
    "process_access": [(SYSMON, 10)],
    "file_event": [(SYSMON, 11)],
    "registry_event": [(SYSMON, n) for n in (12, 13, 14)],
    "registry_add": [(SYSMON, 12)],
    "registry_delete": [(SYSMON, 12)],
    "registry_set": [(SYSMON, 13)],
    "registry_rename": [(SYSMON, 14)],
    "create_stream_hash": [(SYSMON, 15)],
    "pipe_created": [(SYSMON, 17), (SYSMON, 18)],
    "wmi_event": [(SYSMON, n) for n in (19, 20, 21)],
    "dns_query": [(SYSMON, 22)],
    "file_delete": [(SYSMON, 23)],
    "clipboard_capture": [(SYSMON, 24)],
    "process_tampering": [(SYSMON, 25)],
    "file_delete_detected": [(SYSMON, 26)],
    "file_block_executable": [(SYSMON, 27)],
    "file_block_shredding": [(SYSMON, 28)],
    "file_executable_detected": [(SYSMON, 29)],
    "sysmon_error": [(SYSMON, 255)],
    "ps_script": [(POWERSHELL, 4104), ("PowerShellCore/Operational", 4104)],
    "ps_module": [(POWERSHELL, 4103), ("PowerShellCore/Operational", 4103)],
    "ps_classic_start": [("Windows PowerShell", 400)],
    "ps_classic_provider_start": [("Windows PowerShell", 600)],
}
SERVICES = {
    "security": ["Security"],
    "system": ["System"],
    "application": ["Application"],
    "sysmon": [SYSMON],
    "powershell-classic": ["Windows PowerShell"],
    "windefend": ["Microsoft-Windows-Windows Defender/Operational"],
    "codeintegrity-operational": ["Microsoft-Windows-CodeIntegrity/Operational"],
    "firewall-as": ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"],
    "bits-client": ["Microsoft-Windows-Bits-Client/Operational"],
    "appxdeployment-server": ["Microsoft-Windows-AppXDeploymentServer/Operational"],
    "appxpackaging-om": ["Microsoft-Windows-AppxPackaging/Operational"],
    "msexchange-management": ["MSExchange Management"],
    "dns-client": ["Microsoft-Windows-DNS Client Events/Operational"],
    "dns-server": ["DNS Server"],
    "iis-configuration": ["Microsoft-IIS-Configuration/Operational"],
    "taskscheduler": ["Microsoft-Windows-TaskScheduler/Operational"],
    "ntlm": ["Microsoft-Windows-NTLM/Operational"],
    "applocker": [
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ],
    "wmi": ["Microsoft-Windows-WMI-Activity/Operational"],
    "security-mitigations": ["Microsoft-Windows-Security-Mitigations/Kernel Mode", "Microsoft-Windows-Security-Mitigations/User Mode"],
    "microsoft-servicebus-client": ["Microsoft-ServiceBus-Client"],
    "certificateservicesclient-lifecycle-system": ["Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational"],
    "capi2": ["Microsoft-Windows-CAPI2/Operational"],
    "ldap": ["Microsoft-Windows-LDAP-Client/Debug"],
    "openssh": ["OpenSSH/Operational", "OpenSSH/Admin"],
    "shell-core": ["Microsoft-Windows-Shell-Core/Operational"],
    "terminalservices-localsessionmanager": ["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"],
    "appmodel-runtime": ["Microsoft-Windows-AppModel-Runtime/Admin"],
    "driver-framework": ["Microsoft-Windows-DriverFrameworks-UserMode/Operational"],
    "lsa-server": ["Microsoft-Windows-LSA/Operational"],
    "diagnosis-scripted": ["Microsoft-Windows-Diagnosis-Scripted/Operational"],
    "smbclient-security": ["Microsoft-Windows-SMBClient/Security"],
    "smbserver-connectivity": ["Microsoft-Windows-SMBServer/Connectivity"],
}
# These Sigma categories require telemetry Windows Event Log/Sysmon does not supply.
EXCLUDED_CATEGORIES = frozenset({"file_access", "file_rename"})

# ECS aliases complement native winlog.event_data, which takes precedence.
ECS_FIELDS = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ProcessId": "process.pid",
    "ProcessGuid": "process.entity_id",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "ParentProcessId": "process.parent.pid",
    "ParentProcessGuid": "process.parent.entity_id",
    "OriginalFileName": "process.pe.original_file_name",
    "CurrentDirectory": "process.working_directory",
    "User": "user.name",
    "Company": "process.pe.company",
    "Description": "process.pe.description",
    "Product": "process.pe.product",
    "FileVersion": "process.pe.file_version",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "SourceHostname": "source.domain",
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "DestinationHostname": "destination.domain",
    "Protocol": "network.transport",
    "DestinationPortName": "network.protocol",
    "TargetFilename": "file.path",
    "ImageLoaded": "file.path",
    "PipeName": "file.name",
    "TargetObject": "registry.path",
    "QueryName": "dns.question.name",
    "QueryStatus": "sysmon.dns.status",
    "Signed": "file.code_signature.signed",
    "SignatureStatus": "file.code_signature.status",
    "Signature": "file.code_signature.subject_name",
    "Imphash": "file.pe.imphash",
}


def _get(event: dict, path: str):
    if path in event:
        return event[path]
    value = event
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _scalar(value):
    return value.get("#text", value.get("value")) if isinstance(value, dict) else value


def normalize_event(event: dict) -> dict:
    """Project evidence into existing analytics fields without discarding its source."""
    root = event.get("Event", event)
    root = root if isinstance(root, dict) else {}
    system = root.get("System") or {}
    system = system if isinstance(system, dict) else {}
    data = root.get("EventData") or _get(event, "winlog.event_data") or {}
    result = {**(data if isinstance(data, dict) else {}), **event}
    aliases = {
        "EventID": _scalar(system.get("EventID")) or _get(event, "winlog.event_id") or _get(event, "event.code"),
        "Computer": system.get("Computer") or _get(event, "winlog.computer_name") or _get(event, "host.name"),
        "Timestamp": _get(system, "TimeCreated.#attributes.SystemTime")
        or _get(system, "TimeCreated_attributes.SystemTime")
        or _get(system, "TimeCreated.SystemTime")
        or event.get("@timestamp")
        or result.get("UtcTime"),
    }
    aliases.update({field: _get(event, path) for field, path in ECS_FIELDS.items()})
    for key, value in aliases.items():
        if result.get(key) is None and value is not None:
            result[key] = value
    if str(result.get("EventID")) == "4688" and "_logstotal_source" in event:
        # Evaluation aliases use Sysmon's ProcessId semantics. Existing evidence
        # consumers use Security's native names: ProcessId is the creator PID.
        result["NewProcessId"] = result.get("NewProcessId") or result.get("ProcessId")
        result["ProcessId"] = result.get("ParentProcessId")
    return result


def input_filter(log_type: str) -> str:
    """RSigma's embedded jq adds Sigma aliases while retaining the original event."""
    scalar = """
        def obj: if type == "object" then . else {} end;
        def scalar: if type == "object" then .["#text"] // .value else . end;
        def field($path): .[$path] // getpath($path | split("."));
        def userdata:
            reduce to_entries[] as $item ({};
                . + (if ($item.value | type) == "object" then
                    if ($item.value | has("#text")) then {($item.key): ($item.value | scalar)}
                    else ($item.value | userdata) end
                else {($item.key): $item.value} end));
        def eventdata:
            . as $data | (.Data // []) |
            (if type == "array" then . else [.] end) |
            map(select(type == "object") |
                {key: (.["@Name"] // ."#attributes".Name // .Name), value: (. | scalar)} |
                select(.key != null)) | from_entries | . + $data;
    """
    if log_type == "json_winlogbeat":
        alias = ", ".join(f"{json.dumps(k)}: (.{json.dumps(k)} // field({json.dumps(path)}))" for k, path in ECS_FIELDS.items())
        body = (
            """(field("winlog.channel") // .Channel) as $channel |
            . + (field("winlog.user_data") // {} | userdata) + (field("winlog.event_data") // {} | eventdata) | . + {"""
            + alias
            + """, EventID: (field("winlog.event_id") // field("event.code") // .EventID | scalar),
                Channel: (.Channel // $channel), _logstotal_channel: $channel,
                Computer: (field("winlog.computer_name") // field("host.name") // .Computer),
                Timestamp: (."@timestamp" // .Timestamp),
                Provider_Name: (field("winlog.provider_name") // field("event.provider") // .Provider_Name)}"""
        )
    else:
        body = """(.Event // . | obj) as $r | ($r.System | obj) as $s |
            ($s.TimeCreated | obj) as $tc | ($s.Provider | obj) as $p |
            ($s.Channel // .Channel) as $channel |
            . + ($r.UserData // {} | userdata) + ($r.EventData // {} | eventdata) | . + {
                EventID: ($s.EventID // .EventID | scalar), Channel: (.Channel // $channel), _logstotal_channel: $channel,
                Computer: ($s.Computer // .Computer),
                Timestamp: ($tc."#attributes".SystemTime // $s.TimeCreated_attributes.SystemTime //
                    $tc.SystemTime // ($s.TimeCreated | scalar) // .Timestamp // .UtcTime),
                Provider_Name: ($p."#attributes".Name // $s.Provider_attributes.Name //
                    ($s.Provider | scalar) // .Provider_Name)}"""
    # Security/4688 uses different process field names from Sysmon. The source key
    # carries the pair intact; no rule can match a Security/1 by accident.
    return (
        scalar
        + body
        + " | . + {Provider_Name: (.Provider_Name // ("
        + json.dumps(PROVIDERS)
        + "[._logstotal_channel]))}"
        + ' | if ._logstotal_channel == "Security" and (.EventID | tostring) == "4688" then . + {Image: (.NewProcessName // .Image), ParentImage: (.ParentProcessName // .ParentImage), ParentProcessId: (.ProcessId // .ParentProcessId), ProcessId: (.NewProcessId // .ProcessId)} else . end | . + {_logstotal_source: ((.Provider_Name // "") + ":" + (._logstotal_channel // "") + ":" + (.EventID | tostring))}'
    )


def windows_pipeline() -> dict:
    transforms = []
    for category, sources in CATEGORIES.items():
        transforms.append(
            {
                "id": "category_" + category,
                "type": "add_condition",
                "conditions": {"_logstotal_source": [f"{PROVIDERS[channel]}:{channel}:{eid}" for channel, eid in sources]},
                "rule_conditions": [{"type": "logsource", "product": "windows", "category": category}],
            }
        )
    for service, channels in SERVICES.items():
        transforms.append(
            {
                "id": "service_" + service,
                "type": "add_condition",
                "conditions": {"_logstotal_channel": channels},
                "rule_conditions": [{"type": "logsource", "product": "windows", "service": service}],
            }
        )
    for category in sorted(EXCLUDED_CATEGORIES):
        transforms.append(
            {
                "id": "unavailable_" + category,
                "type": "add_condition",
                "conditions": {"_logstotal_source": "unsupported:" + category},
                "rule_conditions": [{"type": "logsource", "category": category}],
            }
        )
    return {"name": "logstotal_windows", "priority": 10, "transformations": transforms}
