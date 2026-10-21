
import math


# Numeric values defined by the CVSS v3.1 specification.
ATTACK_VECTOR = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}

ATTACK_COMPLEXITY = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

PRIVILEGES_REQUIRED = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}

USER_INTERACTION = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}

IMPACT_VALUE = {
    "N": 0.00,  # None
    "L": 0.22,  # Low
    "H": 0.56,  # High
}


def roundup(value):
    """Round up to one decimal place, as CVSS v3.1 requires."""
    return math.ceil((value - 1e-10) * 10) / 10


def severity_rating(score):
    """Convert a CVSS score into its qualitative severity rating."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def calculate_base_score(av, ac, pr, ui, scope, c, i, a):
    """Calculate the CVSS v3.1 Base Score from eight metrics."""

    # Validate the selected metrics before calculating.
    if av not in ATTACK_VECTOR:
        raise ValueError("Invalid Attack Vector")
    if ac not in ATTACK_COMPLEXITY:
        raise ValueError("Invalid Attack Complexity")
    if scope not in PRIVILEGES_REQUIRED:
        raise ValueError("Scope must be U or C")
    if pr not in PRIVILEGES_REQUIRED[scope]:
        raise ValueError("Invalid Privileges Required")
    if ui not in USER_INTERACTION:
        raise ValueError("Invalid User Interaction")

    for metric in (c, i, a):
        if metric not in IMPACT_VALUE:
            raise ValueError("Impact must be N, L, or H")

    # 1. Calculate the Impact Sub-Score (ISS).
    iss = 1 - (
        (1 - IMPACT_VALUE[c])
        * (1 - IMPACT_VALUE[i])
        * (1 - IMPACT_VALUE[a])
    )

    # 2. Calculate the Impact score, depending on Scope.
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = (
            7.52 * (iss - 0.029)
            - 3.25 * ((iss - 0.02) ** 15)
        )

    # 3. If there is no impact, the Base Score is zero.
    if impact <= 0:
        return 0.0

    # 4. Calculate the Exploitability sub-score.
    exploitability = (
        8.22
        * ATTACK_VECTOR[av]
        * ATTACK_COMPLEXITY[ac]
        * PRIVILEGES_REQUIRED[scope][pr]
        * USER_INTERACTION[ui]
    )

    # 5. Calculate the Base Score.
    if scope == "U":
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(
            1.08 * (impact + exploitability), 10
        )

    return roundup(base_score)


def create_vector(av, ac, pr, ui, scope, c, i, a):
    """Create a CVSS v3.1 Base vector string."""
    # Validate metrics using the same rules as the calculator.
    calculate_base_score(av, ac, pr, ui, scope, c, i, a)

    return (
        f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}"
        f"/S:{scope}/C:{c}/I:{i}/A:{a}"
    )
