"""
Risk scoring and evaluation for command analysis.
"""

from .colors import BRIGHT_GREEN, BRIGHT_CYAN, BRIGHT_YELLOW, BRIGHT_RED, BRIGHT_PURPLE
from .config import RISK_MAX, RISK_LEVELS, RISK_RULES


def score_command(command_line):
    """
    Score a command based on risk rules.
    
    Returns:
        tuple: (total_score, reasons_list)
    """
    if not command_line:
        return (0, [])

    total_score = 0
    reasons = []
    seen_reasons = set()

    for pattern, contribution, reason in RISK_RULES:
        if pattern.search(command_line):
            if reason not in seen_reasons:
                reasons.append(reason)
                seen_reasons.add(reason)
            total_score += contribution

    if total_score > RISK_MAX:
        total_score = RISK_MAX

    if total_score < 0:
        total_score = 0

    return (total_score, reasons)


def risk_level_name(score):
    """Get the risk level name for a given score."""
    name = "safe"
    for threshold, level_name, _color in RISK_LEVELS:
        if score >= threshold:
            name = level_name
    return name


def risk_color(score):
    """Get the ANSI color code for a given risk score."""
    color = BRIGHT_GREEN
    for threshold, _name, level_color in RISK_LEVELS:
        if score >= threshold:
            color = level_color
    return color
