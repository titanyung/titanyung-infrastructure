"""One exact authenticated HKT3 reverse bridge; never generic loopback hops."""
import copy
from routing_contract import need

HKT3 = {
    'schema': 1,
    'id': 'uzuma-hkt3-reverse-20261109',
    'provider_instance': 'f30500ac-6220-4eec-9ec9-3ac5777cc893',
    'peer_host_key_fingerprint': 'SHA256:Juv78UAmDK/kHjBkEAxjYE7geGMzcKGG3pL31pX0aTY',
    'proxy_endpoint': {'server': '127.0.0.1', 'server_port': 19421},
    'management_endpoint': {'server': '127.0.0.1', 'server_port': 19521},
    'peer_proxy_endpoint': {'server': '127.0.0.1', 'server_port': 21019},
    'peer_management_endpoint': {'server': '127.0.0.1', 'server_port': 22},
}

def validate_bridges(value):
    need(isinstance(value, dict) and set(value) == {'uzuma-hkt'} and value['uzuma-hkt'] == HKT3,
         'exact_hkt3_reverse_bridge_contract_required')
    return copy.deepcopy(value)

def transport_exception(tag, transport, bridges):
    """Caller may use a public stand-in only for legacy field validation.

    The returned transport is not modified. Runtime still dials the exact
    verified loopback listener, whose live ownership is a deployment gate.
    """
    if tag != 'uzuma-hkt' or not bridges:
        return False
    validate_bridges(bridges)
    need(transport.get('type') == 'shadowsocks'
         and transport.get('method') == '2022-blake3-aes-128-gcm'
         and transport.get('server') == '127.0.0.1' and transport.get('server_port') == 19421,
         'hkt3_exact_reverse_ss2022_transport_required')
    need(not any(k in transport for k in ('detour', 'bind_interface', 'inet4_bind_address', 'inet6_bind_address')),
         'hkt3_reverse_transport_must_not_bind_public_source')
    return True
