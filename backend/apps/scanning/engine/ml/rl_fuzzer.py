"""
Reinforcement Learning Fuzzer — Adaptive payload selection using epsilon-greedy
Q-learning to optimise which payloads work best for each technology stack.

The agent maintains a Q-table mapping (state, action_index) → expected reward.
After each test, rewards are computed from the HTTP response and the Q-table is
updated using the TD(0) rule:

    Q(s, a) ← Q(s, a) + α · [r + γ · max Q(s', a') - Q(s, a)]

State encoding:
    (tech_stack, waf_detected, last_response_type)

Action:
    index into a candidate payload list

Reward:
    +1.00  — 5xx error with vulnerability keywords
    +0.80  — payload reflected in response
    +0.60  — anomalous response (length/time spike)
    +0.40  — interesting status code (403→bypass, 302→redirect)
    -0.50  — WAF block (429 / 403 + "blocked" message)
     0.00  — normal response
"""
from __future__ import annotations

import logging
import random
from collections import defaultdict
from typing import NamedTuple

logger = logging.getLogger(__name__)


# ── State representation ──────────────────────────────────────────────────────

class RLFuzzerState(NamedTuple):
    """Immutable state token used as Q-table key component."""
    tech_stack: str          # php / java / python / aspnet / nodejs / unknown
    waf_detected: bool
    last_response_type: str  # normal / error / blocked / timeout / reflected


# ── Response type classifier ──────────────────────────────────────────────────

import re as _re

_ERROR_SIGNALS = _re.compile(
    r'(exception|traceback|fatal\s+error|stack\s+trace|ORA-\d{5}|'
    r'mysql.*error|syntax\s+error)',
    _re.I,
)
_BLOCK_SIGNALS = _re.compile(
    r'(blocked|security\s+violation|waf\s+detected|access\s+denied'
    r'|firewall|request\s+rejected)',
    _re.I,
)
_REFLECT_SIGNALS = _re.compile(
    r'(<script|javascript:|onerror=|onload=|alert\(|eval\()',
    _re.I,
)


def classify_response_type(response: dict) -> str:
    """Classify an HTTP response into a fuzzer-relevant type."""
    status = response.get('status_code', 200)
    text = response.get('text', '') or ''
    elapsed = response.get('elapsed', 0.0)

    if elapsed > 5.0:
        return 'timeout'
    if status == 429 or (status == 403 and _BLOCK_SIGNALS.search(text)):
        return 'blocked'
    if status >= 500 and _ERROR_SIGNALS.search(text):
        return 'error'
    if _REFLECT_SIGNALS.search(text):
        return 'reflected'
    return 'normal'


# ── Q-learning agent ──────────────────────────────────────────────────────────

class RLFuzzer:
    """Epsilon-greedy Q-learning agent with decay and experience replay."""

    def __init__(
        self,
        epsilon: float = 0.20,
        alpha: float = 0.10,
        gamma: float = 0.90,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.05,
        replay_size: int = 500,
        replay_batch: int = 16,
    ):
        """
        Args:
            epsilon:       exploration rate (0–1). Higher = more random choices.
            alpha:         learning rate (0–1).
            gamma:         discount factor (0–1) for future rewards.
            epsilon_decay: multiply epsilon by this after each update.
            epsilon_min:   floor for epsilon.
            replay_size:   max transitions in experience replay buffer.
            replay_batch:  mini-batch size for replay learning.
        """
        if not (0.0 <= epsilon <= 1.0):
            raise ValueError(f'epsilon must be in [0, 1], got {epsilon}')
        if not (0.0 < alpha <= 1.0):
            raise ValueError(f'alpha must be in (0, 1], got {alpha}')

        self.epsilon = epsilon
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min

        # Q-table: (state_key, action_idx) → float
        self._q_table: dict[tuple, float] = defaultdict(float)
        self._total_updates = 0
        self._total_exploits = 0
        self._total_explores = 0

        # Experience replay buffer
        self._replay_buffer: list[tuple] = []
        self._replay_size = replay_size
        self._replay_batch = replay_batch

    # ── Public API ────────────────────────────────────────────────────────

    def select_payload(
        self, state: RLFuzzerState, candidate_payloads: list[str],
    ) -> tuple[int, str]:
        """Select a payload using epsilon-greedy policy.

        Returns:
            (index, payload_string)
        """
        if not candidate_payloads:
            raise ValueError('candidate_payloads must not be empty')

        n = len(candidate_payloads)

        if random.random() < self.epsilon:
            # Explore: random choice
            idx = random.randrange(n)
            self._total_explores += 1
        else:
            # Exploit: pick action with highest Q-value
            q_values = [self._q_table[(self._state_key(state), i)] for i in range(n)]
            idx = q_values.index(max(q_values))
            self._total_exploits += 1

        return idx, candidate_payloads[idx]

    def update(
        self,
        state: RLFuzzerState,
        action_idx: int,
        reward: float,
        next_state: RLFuzzerState | None = None,
    ) -> None:
        """Perform a TD(0) Q-table update with experience replay.

        Q(s, a) ← Q(s, a) + α · [r + γ · max_a' Q(s', a') - Q(s, a)]
        """
        # Store transition in replay buffer
        self._store_transition(state, action_idx, reward, next_state)

        # Direct update
        self._td_update(state, action_idx, reward, next_state)
        self._total_updates += 1

        # Experience replay: learn from random past transitions
        self._replay_learn()

        # Epsilon decay
        self.epsilon = max(self.epsilon_min,
                           self.epsilon * self.epsilon_decay)

    def _td_update(self, state, action_idx, reward, next_state):
        """Single TD(0) update."""
        s_key = self._state_key(state)
        current_q = self._q_table[(s_key, action_idx)]

        if next_state is not None:
            ns_key = self._state_key(next_state)
            max_future = max(
                self._q_table.get((ns_key, a), 0.0) for a in range(10)
            )
            target = reward + self.gamma * max_future
        else:
            target = reward

        self._q_table[(s_key, action_idx)] = (
            current_q + self.alpha * (target - current_q)
        )

    def _store_transition(self, state, action_idx, reward, next_state):
        """Add transition to the replay buffer (circular)."""
        if len(self._replay_buffer) >= self._replay_size:
            self._replay_buffer.pop(0)
        self._replay_buffer.append((state, action_idx, reward, next_state))

    def _replay_learn(self):
        """Sample a mini-batch from the buffer and learn."""
        if len(self._replay_buffer) < self._replay_batch:
            return
        batch = random.sample(self._replay_buffer, self._replay_batch)
        for s, a, r, ns in batch:
            self._td_update(s, a, r, ns)

    def compute_reward(self, response: dict) -> float:
        """Compute reward signal from an HTTP response.

        Returns:
            float in [-0.5, 1.0]
        """
        status = response.get('status_code', 200)
        text = response.get('text', '') or ''
        elapsed = response.get('elapsed', 0.0)
        response_type = classify_response_type(response)

        if response_type == 'error':
            return 1.00
        if response_type == 'reflected':
            return 0.80
        if response_type == 'blocked':
            return -0.50
        if response_type == 'timeout':
            return 0.60  # potential blind injection

        # Interesting status codes
        if status in (302, 301) and 'admin' in (response.get('location', '') or '').lower():
            return 0.40
        if status == 403 and len(text) > 10_000:
            return 0.30  # bypass hint (verbose 403)
        if elapsed > 3.0:
            return 0.50  # time-based signal

        return 0.00

    def get_best_payloads(
        self,
        state: RLFuzzerState,
        candidates: list[str],
        top_k: int = 5,
    ) -> list[tuple[int, str, float]]:
        """Return top_k payloads ranked by current Q-value.

        Returns:
            list of (index, payload, q_value) sorted descending
        """
        s_key = self._state_key(state)
        ranked = [
            (i, p, self._q_table[(s_key, i)])
            for i, p in enumerate(candidates)
        ]
        ranked.sort(key=lambda x: x[2], reverse=True)
        return ranked[:top_k]

    def get_stats(self) -> dict:
        """Return agent statistics."""
        return {
            'q_table_size': len(self._q_table),
            'total_updates': self._total_updates,
            'total_exploits': self._total_exploits,
            'total_explores': self._total_explores,
            'exploration_rate': self.epsilon,
        }

    def encode_state_from_response(
        self, response: dict, tech_stack: str, waf_detected: bool,
    ) -> RLFuzzerState:
        """Build next state from a response."""
        return RLFuzzerState(
            tech_stack=tech_stack.lower() if tech_stack else 'unknown',
            waf_detected=waf_detected,
            last_response_type=classify_response_type(response),
        )

    # ── Internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _state_key(state: RLFuzzerState) -> str:
        return f'{state.tech_stack}|{int(state.waf_detected)}|{state.last_response_type}'
