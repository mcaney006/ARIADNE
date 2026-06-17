"""Competing-explanation modelling, done explicitly.

A case is never "97% malicious" from an opaque score. Instead every hypothesis
carries a list of named *indicators*; each indicator either supports or
contradicts the hypothesis and contributes a stated weight when its signal is
present. Scoring is a transparent additive model normalised with a softmax, so
the ranking is reproducible and every contribution is auditable.

The signal vocabulary is intentionally shared across scenarios. The departing
engineer, the compromised developer, and the privileged administrator all draw
from the same indicators; what separates their conclusions is *which signals are
present*, not a different model. That is the whole point — same evidence model,
different evidence.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Indicator:
    """One named signal's contribution to a hypothesis."""

    signal: str
    weight: float
    supports: bool = True
    note: str = ""

    def describe(self) -> str:
        arrow = "supports" if self.supports else "contradicts"
        label = self.note or self.signal.replace("_", " ")
        return f"{label} ({arrow}, w={self.weight:g})"


@dataclass(frozen=True)
class Hypothesis:
    """A candidate explanation with explicit supporting/contradicting indicators."""

    id: str
    label: str
    indicators: tuple[Indicator, ...] = ()
    prior: float = 0.0
    malicious: bool = False


@dataclass
class HypothesisScore:
    """The evaluated standing of one hypothesis against a set of signals."""

    hypothesis: Hypothesis
    score: float
    probability: float
    supporting: list[Indicator] = field(default_factory=list)
    contradicting: list[Indicator] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.hypothesis.label


def evaluate_hypotheses(
    hypotheses: list[Hypothesis], signals: dict[str, object]
) -> list[HypothesisScore]:
    """Score and rank hypotheses against present signals.

    A signal "is present" when its value is truthy. Supporting indicators add
    their weight when present; contradicting indicators subtract it. Scores are
    converted to a probability distribution with a softmax so the numbers are
    comparable and sum to one, while remaining a pure function of the inputs.
    """

    raw: list[HypothesisScore] = []
    for hypothesis in hypotheses:
        score = hypothesis.prior
        supporting: list[Indicator] = []
        contradicting: list[Indicator] = []
        for indicator in hypothesis.indicators:
            if not signals.get(indicator.signal):
                continue
            if indicator.supports:
                score += indicator.weight
                supporting.append(indicator)
            else:
                score -= indicator.weight
                contradicting.append(indicator)
        raw.append(
            HypothesisScore(
                hypothesis=hypothesis,
                score=score,
                probability=0.0,
                supporting=supporting,
                contradicting=contradicting,
            )
        )

    max_score = max((s.score for s in raw), default=0.0)
    exps = [math.exp(s.score - max_score) for s in raw]
    total = sum(exps) or 1.0
    for item, exp in zip(raw, exps):
        item.probability = exp / total

    raw.sort(key=lambda s: (-s.probability, s.hypothesis.id))
    return raw


def default_hypotheses() -> list[Hypothesis]:
    """The standard insider-risk hypothesis set (H1–H6)."""

    return [
        Hypothesis(
            id="H1",
            label="Malicious insider collection",
            malicious=True,
            prior=0.0,
            indicators=(
                Indicator("bulk_restricted_clone", 1.4, note="bulk restricted-repo cloning"),
                Indicator("first_seen_access", 0.8, note="first access to restricted repos"),
                Indicator("archive_created", 0.9, note="encrypted archive created"),
                Indicator("removable_media_write", 1.1, note="archive staged to removable media"),
                Indicator("endpoint_telemetry_stopped", 1.0, note="endpoint telemetry stopped"),
                Indicator("shell_history_deleted", 0.7, note="shell history deleted"),
                Indicator("device_enrolled", 0.6, note="activity from enrolled corporate device"),
                Indicator("approval_present", 1.6, supports=False, note="approved change ticket"),
                Indicator("no_endpoint_activity", 1.2, supports=False, note="no endpoint activity on device"),
            ),
        ),
        Hypothesis(
            id="H2",
            label="Compromised developer credentials",
            malicious=True,
            prior=0.0,
            indicators=(
                Indicator("new_token_created", 1.0, note="new access token created"),
                Indicator("auth_from_unusual_infra", 1.4, note="auth from unusual infrastructure"),
                Indicator("no_endpoint_activity", 1.5, note="no endpoint activity on enrolled device"),
                Indicator("cloud_object_retrieval", 0.8, note="cloud object retrieval"),
                Indicator("removable_media_write", 1.0, supports=False, note="local removable-media staging"),
                Indicator("device_enrolled", 0.7, supports=False, note="activity from enrolled device"),
            ),
        ),
        Hypothesis(
            id="H3",
            label="Authorized migration",
            malicious=False,
            prior=0.0,
            indicators=(
                Indicator("approval_present", 2.2, note="approved change ticket present"),
                Indicator("legitimate_access", 1.0, note="user has legitimate engineering access"),
                Indicator("device_enrolled", 0.6, note="enrolled corporate device"),
                Indicator("endpoint_telemetry_stopped", 1.2, supports=False, note="telemetry stopped"),
                Indicator("shell_history_deleted", 1.0, supports=False, note="shell history deleted"),
            ),
        ),
        Hypothesis(
            id="H4",
            label="Security-team testing",
            malicious=False,
            prior=-0.5,
            indicators=(
                Indicator("security_team_actor", 1.8, note="actor belongs to security team"),
                Indicator("approval_present", 0.6, note="change ticket present"),
            ),
        ),
        Hypothesis(
            id="H5",
            label="Privileged administrator abuse",
            malicious=True,
            prior=0.0,
            indicators=(
                Indicator("logging_disabled", 1.2, note="logging disabled"),
                Indicator("outside_maintenance_window", 1.3, note="action outside maintenance window"),
                Indicator("unseen_device", 1.1, note="previously unseen device"),
                Indicator("temp_identity_created", 1.0, note="temporary privileged identity created"),
                Indicator("temp_identity_deleted", 0.8, note="temporary identity deleted"),
                Indicator("approval_present", 1.4, supports=False, note="approved maintenance ticket"),
            ),
        ),
        Hypothesis(
            id="H6",
            label="Broken automation",
            malicious=False,
            prior=-1.0,
            indicators=(
                Indicator("automation_actor", 1.6, note="actor is a service/automation account"),
                Indicator("shell_history_deleted", 1.0, supports=False, note="interactive shell history deleted"),
                Indicator("removable_media_write", 1.0, supports=False, note="removable-media staging"),
            ),
        ),
    ]
