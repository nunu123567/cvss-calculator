import unittest

from cvss import (
    calculate_base_score,
    calculate_base_score_details,
    create_vector,
    severity_rating,
)


class TestCVSSCalculator(unittest.TestCase):

    def test_critical_score_98(self):
        """Network attack with no privileges and high impacts."""
        score = calculate_base_score(
            "N", "L", "N", "N", "U", "H", "H", "H"
        )
        self.assertEqual(score, 9.8)
        self.assertEqual(severity_rating(score), "Critical")

    def test_official_mysql_example(self):
        """FIRST example: MySQL stored SQL injection."""
        score = calculate_base_score(
            "N", "L", "L", "N", "C", "L", "L", "N"
        )
        self.assertEqual(score, 6.4)
        self.assertEqual(severity_rating(score), "Medium")

    def test_zero_impact(self):
        """No confidentiality, integrity, or availability impact."""
        score = calculate_base_score(
            "N", "L", "N", "N", "U", "N", "N", "N"
        )
        self.assertEqual(score, 0.0)
        self.assertEqual(severity_rating(score), "None")

    def test_invalid_attack_vector(self):
        """Invalid metric values must be rejected."""
        with self.assertRaises(ValueError):
            calculate_base_score(
                "X", "L", "N", "N", "U", "H", "H", "H"
            )

    def test_invalid_privileges(self):
        """Privileges must use an allowed value."""
        with self.assertRaises(ValueError):
            calculate_base_score(
                "N", "L", "X", "N", "U", "H", "H", "H"
            )

    def test_vector_string(self):
        vector = create_vector(
            "N", "L", "N", "N", "U", "H", "H", "H"
        )
        self.assertEqual(
            vector,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )


    def test_calculation_breakdown(self):
        details = calculate_base_score_details(
            "N", "L", "N", "N", "U", "H", "H", "H"
        )

        self.assertAlmostEqual(details["iss"], 0.914816, places=6)
        self.assertAlmostEqual(details["impact"], 5.8731, places=3)
        self.assertAlmostEqual(
            details["exploitability"], 3.8870, places=3
        )
        self.assertEqual(details["score"], 9.8)
        self.assertEqual(details["severity"], "Critical")


    def test_all_scope_privilege_combinations(self):
        # Expected scores for a fixed set of metrics.
        # Only Scope and Privileges Required change.
        cases = [
            ("U", "N", 8.2),
            ("U", "L", 7.1),
            ("U", "H", 5.5),
            ("C", "N", 9.3),
            ("C", "L", 8.5),
            ("C", "H", 7.6),
        ]

        for scope, pr, expected_score in cases:
            with self.subTest(scope=scope, privileges=pr):
                score = calculate_base_score(
                    "N", "L", pr, "N", scope, "H", "L", "N"
                )
                self.assertEqual(score, expected_score)


    def test_minimum_score(self):
        score = calculate_base_score(
            "N", "L", "N", "N", "U", "N", "N", "N"
        )
        self.assertEqual(score, 0.0)

    def test_maximum_score(self):
        score = calculate_base_score(
            "N", "L", "N", "N", "C", "H", "H", "H"
        )
        self.assertEqual(score, 10.0)


    def test_severity_boundaries(self):
        cases = [
            (0.0, "None"),
            (0.1, "Low"),
            (3.9, "Low"),
            (4.0, "Medium"),
            (6.9, "Medium"),
            (7.0, "High"),
            (8.9, "High"),
            (9.0, "Critical"),
            (10.0, "Critical"),
        ]

        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(
                    severity_rating(score), expected
                )


    def test_invalid_privileges_for_scope(self):
        with self.assertRaises(ValueError):
            calculate_base_score(
                "N", "L", "X", "N", "U", "H", "H", "H"
            )


if __name__ == "__main__":
    unittest.main()
