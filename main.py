
from cvss import (
    calculate_base_score,
    calculate_base_score_details,
    create_vector,
    severity_rating,
)

def ask_metric(title, options):
    """Display choices and return the selected metric value."""
    print(f"\n{title}")

    for key, description in options.items():
        print(f"  {key} - {description}")

    while True:
        choice = input("Choose an option: ").strip().upper()

        if choice in options:
            return choice

        print("Invalid choice. Please try again.")


def main():
    print("=" * 45)
    print("       CVSS v3.1 BASE SCORE CALCULATOR")
    print("=" * 45)

    av = ask_metric("Attack Vector", {
        "N": "Network",
        "A": "Adjacent",
        "L": "Local",
        "P": "Physical",
    })

    ac = ask_metric("Attack Complexity", {
        "L": "Low",
        "H": "High",
    })

    pr = ask_metric("Privileges Required", {
        "N": "None",
        "L": "Low",
        "H": "High",
    })

    ui = ask_metric("User Interaction", {
        "N": "None",
        "R": "Required",
    })

    scope = ask_metric("Scope", {
        "U": "Unchanged",
        "C": "Changed",
    })

    c = ask_metric("Confidentiality Impact", {
        "N": "None",
        "L": "Low",
        "H": "High",
    })

    i = ask_metric("Integrity Impact", {
        "N": "None",
        "L": "Low",
        "H": "High",
    })

    a = ask_metric("Availability Impact", {
        "N": "None",
        "L": "Low",
        "H": "High",
    })


    try:
        details = calculate_base_score_details(
            av, ac, pr, ui, scope, c, i, a
        )

        vector = create_vector(
            av, ac, pr, ui, scope, c, i, a
        )

        print("\n" + "=" * 45)
        print("       CVSS CALCULATION BREAKDOWN")
        print("=" * 45)

        print(f"Impact Sub-Score (ISS):       {details['iss']:.4f}")
        print(f"Impact Score:                 {details['impact']:.4f}")
        print(
            "Exploitability Sub-Score:     "
            f"{details['exploitability']:.4f}"
        )

        print("-" * 45)
        print(f"CVSS Base Score:              {details['score']:.1f}")
        print(f"Severity:                     {details['severity']}")
        print(f"Vector: {vector}")
        print("=" * 45)

    except ValueError as error:
        print(f"Error: {error}")



if __name__ == "__main__":
    main()
