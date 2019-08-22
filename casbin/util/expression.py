from simpleeval import SimpleEval
import ast


class SimpleEval(SimpleEval):
    """ Rewrite SimpleEval.
        >>> s = SimpleEval("20 + 30 - ( 10 * 5)")
        >>> s.eval()
        0
        """

    ast_parsed_value = None

    def __init__(self, expr, functions=None):
        """Create the evaluator instance.  Set up valid operators (+,-, etc)
            functions (add, random, get_val, whatever) and names. """
        super(SimpleEval, self).__init__(functions=functions)
        if expr != "":
            self.expr = expr
            self.expr_parsed_value = ast.parse(expr.strip()).body[0].value

    def eval(self, names=None):
        """ evaluate an expresssion, using the operators, functions and
                   names previously set up. """

        if names:
            self.names = names

        return self._eval(self.expr_parsed_value)
