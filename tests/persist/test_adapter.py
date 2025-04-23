from casbin.persist.adapter import _extract_tokens
from tests import TestCaseBase


class TestExtractTokens(TestCaseBase):
    def test_ignore_lines(self):
        self.assertIsNone(_extract_tokens(""))  # empty
        self.assertIsNone(_extract_tokens("# comment"))

    def test_simple_lines(self):
        # split on top-level commas, strip whitespace from start and end
        self.assertEqual(_extract_tokens("one"), ["one"])
        self.assertEqual(_extract_tokens("one,two"), ["one", "two"])
        self.assertEqual(_extract_tokens("   ignore  \t,\t   external, spaces  "), ["ignore", "external", "spaces"])

        self.assertEqual(_extract_tokens("internal spaces preserved"), ["internal spaces preserved"])

    def test_nested_lines(self):
        # basic nesting within a single token
        self.assertEqual(
            _extract_tokens("outside1()"),
            ["outside1()"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1())"),
            ["outside1(inside1())"],
        )

        # split on top-level commas, but not on internal ones
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2())"),
            ["outside1(inside1(), inside2())"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2(inside3(), inside4()))"),
            ["outside1(inside1(), inside2(inside3(), inside4()))"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2()), outside2(inside3(), inside4())"),
            ["outside1(inside1(), inside2())", "outside2(inside3(), inside4())"],
        )

        # different delimiters
        self.assertEqual(
            _extract_tokens(
                "all_square[inside1[], inside2[]],square_and_parens[inside1(), inside2()],parens_and_square(inside1[], inside2[])"
            ),
            [
                "all_square[inside1[], inside2[]]",
                "square_and_parens[inside1(), inside2()]",
                "parens_and_square(inside1[], inside2[])",
            ],
        )
