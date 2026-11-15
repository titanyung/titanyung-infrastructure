"""Versioned native-raw port closure; no firewall command executes on import."""
import copy
from policy_inputs import runtime,need

TABLE='dmit_revision_20261109_raw'
OLD_BLOCKED={29514,29515,29516,29517,29518,29519,29611,29614,29615,29616,29617,29618,29619,31117}

def document(plan):
    runtime.validate_network_plan(plan);need(runtime.revised(plan),'new_main_plan_required')
    ports=sorted(OLD_BLOCKED|set(runtime.expected_fronts(plan).values())|{29520,29620})
    # A separate owned table keeps the already enforced old deadline table,
    # Docker, fail2ban, and all unrelated rules intact. inet covers both families.
    text='table inet '+TABLE+' {\n comment "routing-revision-20261109"\n chain input {\n'
    text+=' type filter hook input priority -6; policy accept;\n'
    text+=' iifname != "lo" tcp dport { '+', '.join(map(str,ports))+' } counter reject with tcp reset\n }\n}\n'
    return {'table':TABLE,'ports':ports,'create':text,'replace':'delete table inet '+TABLE+'\n'+text,
            'existing_tables_never_flushed':True,'client_public_alias_ports_affected':False}

def openrc_not_applicable_systemd_unit(command_path):
    need(command_path.startswith('/opt/') and '\n' not in command_path,'reviewed_guard_executable_path_required')
    return '[Unit]\nDescription=Private raw native proxy ingress guard\nBefore=dmit-direct-staging.service\nAfter=network-pre.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart='+command_path+'\n[Install]\nWantedBy=multi-user.target\n'
