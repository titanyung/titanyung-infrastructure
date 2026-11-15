"""Pure selection of an already qualified AI exit; no I/O or wall clock.

Call only after ``qualify_ai_paths`` has verified both sensitive AI sites, TLS,
Singapore and the intended operator ASN. This module consumes that result's
strict ``healthy is True`` flag; it does not infer residence from an IP label.

Desktop/router StarHub traffic chooses between two healthy StarHub transports.
The two sensitive-site request durations are averaged; the ordinary Cloudflare
diagnostic and whole-probe duration never influence selection. A small switching
margin (at most 50ms and 10%) avoids flipping between nearly equal paths, while
a clear improvement takes effect on the next observation. A failed/contaminated
current path is excluded immediately, without waiting for a history window.

The legacy z bit now means *Uzuma StarHub selected*, l means *Lazycat StarHub
selected*, and s means Singtel healthy. z and l are one-hot, giving six legal
V2 modes. Frontend LC-versus-DMIT priority and mobile Singtel preference remain
the caller/native policy's responsibility; this module never selects a frontend.
"""
from __future__ import annotations

import math
from statistics import median

POLICY_ID = 'starhub-qualified-latency-20261108-v1'
SCHEMA = 1
LAZYCAT = 'lazycat-starhub'
UZUMA = 'uzuma-starhub'
SINGTEL = 'uzuma-singtel'
STARHUBS = (LAZYCAT, UZUMA)
LABELS = STARHUBS + (SINGTEL,)
AI_SITES = ('chatgpt.com', 'claude.ai')
MODES = tuple('ai-z' + str(int(selected == UZUMA)) + 's' + str(int(singtel)) +
              'l' + str(int(selected == LAZYCAT))
              for selected in (None, LAZYCAT, UZUMA) for singtel in (False, True))
MAX_SAMPLE_SECONDS = 120.0
MAX_SWITCH_MARGIN_SECONDS = .05
SWITCH_MARGIN_RATIO = .10
HISTORY_SIZE = 3
MAX_STATE_AGE_SECONDS = 180.0
FUTURE_TOLERANCE_SECONDS = 5.0


class SelectionError(ValueError):
    """Fixed error codes only; no endpoint or credential serialization."""


def _number(value, *, positive=False):
    if type(value) not in (int, float):
        return False
    try:
        if not math.isfinite(value):
            return False
    except OverflowError:
        return False
    return value > 0 if positive else value >= 0


def _timestamp(proof, previous, now):
    if now is not None:
        if not _number(now):
            raise SelectionError('invalid_observation_time')
        return float(now)
    if isinstance(proof, dict):
        for key in ('finished_at', 'started_at'):
            if _number(proof.get(key)):
                return float(proof[key])
    # A deterministic logical clock supports owned fixtures and fail-closed
    # malformed proofs. Production probes supply started_at/finished_at.
    if isinstance(previous, dict) and _number(previous.get('checked_at')):
        return float(previous['checked_at']) + 1.0
    return 0.0


def _previous(value, now):
    blank = {'selected_starhub': None, 'samples': {label: [] for label in STARHUBS}}
    if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != SCHEMA:
        return blank
    checked = value.get('checked_at')
    if not _number(checked) or not -FUTURE_TOLERANCE_SECONDS <= now - checked <= MAX_STATE_AGE_SECONDS:
        return blank
    selected = value.get('selected_starhub')
    if selected not in STARHUBS + (None,):
        return blank
    rows = value.get('samples')
    if not isinstance(rows, dict) or set(rows) != set(STARHUBS):
        return blank
    histories = {}
    for label in STARHUBS:
        samples = rows[label]
        if not isinstance(samples, list) or len(samples) > HISTORY_SIZE:
            return blank
        copied = []
        for sample in samples:
            if not isinstance(sample, dict) or set(sample) != {'at', 'seconds'}:
                return blank
            at, seconds = sample['at'], sample['seconds']
            if not _number(at) or not _number(seconds, positive=True) or seconds > MAX_SAMPLE_SECONDS:
                return blank
            if 0 <= now - at <= MAX_STATE_AGE_SECONDS:
                copied.append({'at': float(at), 'seconds': float(seconds)})
        histories[label] = sorted(copied, key=lambda sample: sample['at'])[-HISTORY_SIZE:]
    return {'selected_starhub': selected, 'samples': histories}


def _score(path):
    if not isinstance(path, dict) or path.get('healthy') is not True:
        return None
    checks = path.get('checks')
    if not isinstance(checks, list):
        return None
    sensitive = [row for row in checks if isinstance(row, dict) and row.get('site') in AI_SITES]
    if len(sensitive) != 2 or {row['site'] for row in sensitive} != set(AI_SITES):
        return None
    times = [row.get('time_seconds') for row in sensitive]
    if not all(_number(value, positive=True) and value <= MAX_SAMPLE_SECONDS for value in times):
        return None
    return sum(float(value) for value in times) / 2.0


def choose(proof, previous_state=None, now=None):
    """Return a credential-free mode/decision and the next small state.

    ``previous_state`` is the preceding result's ``state`` value. Supply an
    explicit ``now`` or use the native probe's timestamps. A caller must reset
    state when its edge identity, generation, manifest or policy changes; this
    pure module has no access to those authority files. State older than three
    minutes is ignored. Persisting the returned state is optional.

    Invalid status, missing/duplicate paths, unqualified paths or invalid timing
    samples never reuse a previous healthy flag. A timing failure is unavailable
    for this decision, rather than being fabricated as zero latency.
    """
    checked_at = _timestamp(proof, previous_state, now)
    previous = _previous(previous_state, checked_at)
    scores = {label: None for label in LABELS}
    if isinstance(proof, dict) and proof.get('status') == 'completed' and isinstance(proof.get('paths'), list):
        for label in LABELS:
            matching = [row for row in proof['paths'] if isinstance(row, dict) and row.get('label') == label]
            if len(matching) == 1:
                scores[label] = _score(matching[0])
    health = {label: scores[label] is not None for label in LABELS}
    histories = previous['samples']
    for label in STARHUBS:
        if not health[label]:
            histories[label] = []
        else:
            # Retrying the same observation second replaces, not reweights, it.
            histories[label] = [sample for sample in histories[label] if sample['at'] != checked_at]
            histories[label].append({'at': checked_at, 'seconds': scores[label]})
            histories[label] = histories[label][-HISTORY_SIZE:]
    eligible = [label for label in STARHUBS if health[label]]
    selected = None
    margin = 0.0
    reason = 'no_qualified_starhub'
    if eligible:
        fastest = min(eligible, key=lambda label: (scores[label], STARHUBS.index(label)))
        current = previous['selected_starhub']
        if current in eligible:
            margin = min(MAX_SWITCH_MARGIN_SECONDS, scores[current] * SWITCH_MARGIN_RATIO)
            if fastest != current and scores[current] - scores[fastest] > margin + 1e-12:
                selected, reason = fastest, 'faster_qualified_starhub'
            else:
                selected, reason = current, ('within_switch_margin' if fastest != current else 'current_fastest')
        else:
            selected = fastest
            reason = ('previous_starhub_unavailable' if current is not None else 'fastest_qualified_starhub')
    mode = 'ai-z' + str(int(selected == UZUMA)) + 's' + str(int(health[SINGTEL])) + 'l' + str(int(selected == LAZYCAT))
    state = {'schema': SCHEMA, 'checked_at': checked_at, 'selected_starhub': selected, 'samples': histories}
    return {'policy_id': POLICY_ID, 'mode': mode, 'selected_starhub': selected,
            'health': health, 'scores': scores,
            'median_seconds': {label: median([sample['seconds'] for sample in histories[label]])
                               if histories[label] else None for label in STARHUBS},
            'switch_margin_seconds': margin, 'reason': reason, 'state': state}
