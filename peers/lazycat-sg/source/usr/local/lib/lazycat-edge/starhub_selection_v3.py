"""Preserve all qualified path health while retaining the pool's stable choice."""
from starhub_selection import choose as choose_pool


def choose(proof, previous_state=None, now=None):
    result = choose_pool(proof, previous_state=previous_state, now=now)
    health = result['health']
    selected = result['selected_starhub']
    preferred = {'lazycat-starhub': 'l', 'uzuma-starhub': 'u', None: 'n'}[selected]
    result['mode'] = ('ai-z' + str(int(health['uzuma-starhub'])) +
                      's' + str(int(health['uzuma-singtel'])) +
                      'l' + str(int(health['lazycat-starhub'])) + 'p' + preferred)
    return result
