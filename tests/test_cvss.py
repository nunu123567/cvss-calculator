
import unittest

from cvss import (
    calculate_base_score,
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


if __name__ == "__main__":
    unittest.main()
