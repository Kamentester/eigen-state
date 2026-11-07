"""Bounded intraprocedural abstract paths over Python and JS/TS syntax.

Operation summaries are assumptions, not resolved library identities. Unsupported
syntax and escaped ownership remain explicit gaps. This module never runs input.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import ast
import math

UNKNOWN = ('unknown',)
FUNCTIONS = {'function_definition', 'function_declaration', 'function_expression',
             'arrow_function', 'method_definition', 'generator_function_declaration'}
ASSIGNMENTS = {'assignment', 'assignment_expression', 'variable_declarator'}
BLOCKS = {'block', 'statement_block', 'module', 'program', 'else_clause', 'finally_clause'}
ASSUMPTIONS = [
    'Intraprocedural paths; calls and external mutation are not resolved across functions.',
    'Unknown calls may raise; unknown branch conditions permit either arm.',
    'Python open and awaited JS fs.open/fs.promises.open denote owned file handles.',
    'A successful close releases its handle; a failed close leaves release uncertain.',
]


@dataclass
class Op:
    kind: str
    node: object
    target: str = ''
    expr: object = None
    body: list = field(default_factory=list)
    other: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    final: list = field(default_factory=list)
    catches_all: bool = False


@dataclass
class PathState:
    values: dict = field(default_factory=dict)
    resources: dict = field(default_factory=dict)
    constraints: dict = field(default_factory=dict)
    guards: list = field(default_factory=list)
    trace: list = field(default_factory=list)
    exit: str = 'normal'
    returned: object = UNKNOWN
    witness_truncated: bool = False
    guards_truncated: bool = False

    def __deepcopy__(self, memo):
        return PathState(dict(self.values), {key: dict(value) for key, value in self.resources.items()},
                         dict(self.constraints), list(self.guards), list(self.trace), self.exit, self.returned, self.witness_truncated, self.guards_truncated)


class Syntax:
    """Language adapters lower statements to the shared path operations."""
    def __init__(self, raw, language, gap):
        self.raw, self.language, self.gap = raw, language, gap

    def text(self, node):
        return self.raw[node.start_byte:node.end_byte].decode('utf-8') if node else ''

    def unwrap(self, node):
        while node and node.type in {'parenthesized_expression', 'as_expression', 'non_null_expression', 'type_assertion'}:
            node = node.named_children[0]
        return node

    def name(self, node):
        node = self.unwrap(node)
        if node and node.type in {'identifier', 'attribute', 'member_expression'}:
            return self.text(node)
        return ''

    def literal(self, node):
        node = self.unwrap(node)
        text = self.text(node)
        if text in {'True', 'true'}: return True
        if text in {'False', 'false'}: return False
        if text in {'None', 'null'}: return None
        if node and node.type in {'string', 'integer', 'float', 'number'}:
            try:
                value = ast.literal_eval(text)
                if isinstance(value, (str, int, float)) and len(text) <= 240:
                    if isinstance(value, float) and not math.isfinite(value): return UNKNOWN
                    return value
            except (ValueError, SyntaxError):
                return UNKNOWN
        return UNKNOWN

    def lower(self, node):
        if node is None: return []
        kind = node.type
        if kind in BLOCKS or kind in {'expression_statement', 'lexical_declaration', 'variable_declaration'}:
            return [op for child in node.named_children for op in self.lower(child)]
        if kind in FUNCTIONS or kind in {'class_definition', 'class_declaration'}:
            return []  # Each function has its own initial state and identity.
        if kind in ASSIGNMENTS:
            target = node.child_by_field_name('left') or node.child_by_field_name('name')
            value = node.child_by_field_name('right') or node.child_by_field_name('value')
            name = self.name(target)
            if name: return [Op('assign', node, name, value)]
        if kind in {'if_statement', 'elif_clause'}:
            condition = node.child_by_field_name('condition')
            body = node.child_by_field_name('consequence')
            alternatives = [c for c in node.named_children if c.type in {'elif_clause', 'else_clause'}]
            if len(alternatives) > 120:
                self.gap('branch-depth', node, 'Conditional chain exceeds 120 arms; this branch is skipped.')
                return [Op('unknown', node)]
            if self.language == 'python':
                def chain(items):
                    if not items: return []
                    first = items[0]
                    if first.type == 'else_clause': return self.lower(first)
                    return [Op('branch', first, expr=first.child_by_field_name('condition'),
                               body=self.lower(first.child_by_field_name('consequence')), other=chain(items[1:]))]
                other = chain(alternatives)
            else:
                other = self.lower(node.child_by_field_name('alternative'))
            return [Op('branch', node, expr=condition, body=self.lower(body), other=other)]
        if kind == 'try_statement':
            body = node.child_by_field_name('body')
            if body is None: body = next((c for c in node.named_children if c.type == 'block'), None)
            handlers = [self.lower(c.child_by_field_name('body') or next((b for b in c.named_children if b.type in {'block', 'statement_block'}), None))
                        for c in node.named_children if c.type in {'except_clause', 'catch_clause'}]
            final = next((c for c in node.named_children if c.type == 'finally_clause'), None)
            other = next((c for c in node.named_children if c.type == 'else_clause'), None)
            catches_all = self.language != 'python' or any(c.type == 'except_clause' and c.child_by_field_name('value') is None for c in node.named_children)
            if handlers and not catches_all:
                self.gap('exception-types', node, 'Handler types are overapproximated; an exception may match each handler or escape.')
            return [Op('try', node, body=self.lower(body), handlers=handlers, final=self.lower(final), other=self.lower(other), catches_all=catches_all)]
        if kind in {'return_statement', 'raise_statement', 'throw_statement'}:
            return [Op('return' if kind == 'return_statement' else 'throw', node,
                       expr=node.named_children[0] if node.named_children else None)]
        if kind in {'call', 'call_expression', 'await', 'await_expression', 'new_expression'}:
            return [Op('eval', node, expr=node)]
        if kind in {'comment', 'pass_statement', 'empty_statement', 'import_statement', 'import_from_statement',
                    'type_alias_declaration', 'interface_declaration', 'string', 'identifier'}: return []
        self.gap('unsupported-control', node, 'This construct is outside the path subset: ' + kind)
        return [Op('unknown', node)]


class Checker:
    def __init__(self, raw, language, max_paths):
        self.syntax = Syntax(raw, language, self.gap)
        self.language, self.max_paths = language, max_paths
        self.entries, self.seen, self.candidates = [], set(), {}
        self.scope = '<module>'
        self.scope_id = 0
        self.steps = 0
        self.max_steps = 10000

    def location(self, node):
        return {'line': node.start_point.row + 1, 'column': node.start_point.column + 1,
                'start_byte': node.start_byte, 'end_byte': node.end_byte}

    def emit(self, category, rule, node, detail, state=None, owner=''):
        key = (category, rule, self.scope_id, node.start_byte, owner)
        if key in self.seen: return
        self.seen.add(key)
        if len(self.entries) >= 1000: return
        self.entries.append({'category': category, 'rule': rule, 'scope': self.scope, 'scope_id': self.scope_id,
                             'owner': owner, 'location': self.location(node), 'detail': detail,
                             **({'witness': list(state.trace), 'guards': list(state.guards),
                                 'witness_truncated': state.witness_truncated, 'guards_truncated': state.guards_truncated,
                                 'classification': 'potential', 'assumptions': ASSUMPTIONS} if state is not None else {})})

    def gap(self, rule, node, detail):
        self.emit('gap', rule, node, detail)

    def finding(self, rule, node, detail, state, owner=''):
        self.emit('finding', rule, node, detail, state, owner)

    def mark(self, state, node, event):
        state.witness_truncated |= len(state.trace) >= 24
        state.trace = (state.trace + [{'line': node.start_point.row + 1, 'event': event}])[-24:]

    def bound(self, states, node):
        if len(states) > self.max_paths:
            self.gap('path-budget', node, f'Path set capped at {self.max_paths}; remaining paths omitted.')
        return states[:self.max_paths]

    def transition(self, owner, before, after, node, state):
        if after == UNKNOWN or isinstance(after, tuple): return
        key = (self.scope_id, owner)
        candidate = self.candidates.setdefault(key, {'category': 'candidate', 'rule': 'literal-state',
            'scope': self.scope, 'scope_id': self.scope_id, 'owner': owner, 'location': self.location(node), 'states': [], 'transitions': []})
        if not any(type(after) is type(existing) and after == existing for existing in candidate['states']):
            candidate['states'].append(after)
        row = {'from': '<unknown>' if before == UNKNOWN or isinstance(before, tuple) else before,
               'to': after, 'line': node.start_point.row + 1, 'guards': list(state.guards)}
        if row not in candidate['transitions']: candidate['transitions'].append(row)

    def truth(self, node, state):
        node = self.syntax.unwrap(node)
        value = self.syntax.literal(node)
        if value != UNKNOWN: return bool(value)
        name = self.syntax.name(node)
        if name:
            value = state.values.get(name, UNKNOWN)
            if value != UNKNOWN and not isinstance(value, tuple): return bool(value)
            return state.constraints.get(name)
        if node and node.type in {'not_operator', 'unary_expression'}:
            if self.syntax.text(node).lstrip().startswith(('not ', '!')):
                value = self.truth(node.named_children[-1], state)
                return None if value is None else not value
        if node and node.type in {'comparison_operator', 'binary_expression'} and len(node.named_children) == 2:
            left, right = node.named_children
            operator = self.syntax.raw[left.end_byte:right.start_byte].decode().strip()
            a = state.values.get(self.syntax.name(left), self.syntax.literal(left))
            b = state.values.get(self.syntax.name(right), self.syntax.literal(right))
            if a != UNKNOWN and b != UNKNOWN and not isinstance(a, tuple) and not isinstance(b, tuple):
                if operator in {'is', 'is not'} and not (a is None or b is None or type(a) is bool or type(b) is bool):
                    self.gap('identity-comparison', node, 'Object identity is outside the literal-value abstraction.')
                    return None
                same_type = type(a) is type(b) or (type(a) in {int, float} and type(b) in {int, float})
                if self.language != 'python' and operator in {'==', '!='} and not same_type:
                    self.gap('coercive-equality', node, 'JS coercive equality across different literal types remains unknown.')
                    return None
                if self.language != 'python' and operator in {'===', '!=='} and not same_type:
                    return operator == '!=='
                if operator in {'==', '===', 'is'}: return a == b
                if operator in {'!=', '!==', 'is not'}: return a != b
        return None

    def evaluate(self, node, state, awaited=False):
        node = self.syntax.unwrap(node)
        if node is None: return [(state, UNKNOWN)]
        if node.type in {'await', 'await_expression'}:
            return self.evaluate(node.named_children[-1], state, True)
        literal = self.syntax.literal(node)
        if literal != UNKNOWN: return [(state, literal)]
        name = self.syntax.name(node)
        if name: return [(state, state.values.get(name, UNKNOWN))]
        if node.type not in {'call', 'call_expression', 'new_expression'}:
            self.gap('unknown-expression', node, 'Expression effects and value are outside the subset: ' + node.type)
            return [(state, UNKNOWN)]
        function = node.child_by_field_name('function') or node.child_by_field_name('constructor')
        callee = self.syntax.text(function)
        arguments = node.child_by_field_name('arguments')
        pairs = [(state, [])]
        for argument in (arguments.named_children if arguments else []):
            following = []
            for current, values in pairs:
                if current.exit != 'normal': following.append((current, values)); continue
                for changed, value in self.evaluate(argument, current): following.append((changed, values + [value]))
            if len(following) > self.max_paths: self.gap('path-budget', node, 'Argument paths capped.')
            pairs = following[:self.max_paths]
        results = []
        for current, values in pairs:
            if current.exit != 'normal': results.append((current, UNKNOWN)); continue
            results.extend(self.call(node, callee, values, current, awaited))
        if len(results) > self.max_paths: self.gap('path-budget', node, 'Call paths capped.')
        return results[:self.max_paths]

    def call(self, node, callee, values, state, awaited):
        failed = deepcopy(state)
        failed.exit = 'throw'
        self.mark(failed, node, callee + ' raises')
        acquire = (self.language == 'python' and callee == 'open') or (
            self.language != 'python' and callee in {'fs.open', 'fs.promises.open'} and awaited)
        if acquire:
            identity = (self.scope_id, node.start_byte)
            state.resources[identity] = {'state': 'owned', 'owner': callee, 'node': node}
            self.mark(state, node, callee + ' acquires')
            return [(failed, UNKNOWN), (state, ('resource', identity))]
        receiver, _, method = callee.rpartition('.')
        value = state.values.get(receiver, UNKNOWN)
        if isinstance(value, tuple) and value and value[0] == 'resource':
            resource = state.resources[value[1]]
            if method == 'close':
                if self.language != 'python' and not awaited:
                    self.finding('resource-release-unawaited', node, 'FileHandle.close promise is not awaited.', state, receiver)
                    self.mark(state, node, 'close scheduled; completion unknown')
                    return [(failed, UNKNOWN), (state, UNKNOWN)]
                if resource['state'] == 'released':
                    self.finding('resource-repeated-release', node, 'Release is repeated; check the API idempotency contract.', state, receiver)
                failed.resources[value[1]]['state'] = 'release-unknown'
                resource['state'] = 'released'
                self.mark(state, node, receiver + ' released')
                return [(failed, UNKNOWN), (state, UNKNOWN)]
            if resource['state'] == 'released':
                self.finding('resource-use-after-release', node, 'Handle method invoked after successful release.', state, receiver)
        else:
            self.gap('unknown-call', node, 'Call effects require a summary: ' + callee[:120])
        for value in values:
            if isinstance(value, tuple) and value and value[0] == 'resource':
                self.gap('ownership-escape', node, 'Resource passed to an unsummarised call; ownership becomes uncertain.')
                state.resources[value[1]]['state'] = 'escaped'
                failed.resources[value[1]]['state'] = 'escaped'
        self.mark(state, node, callee + ' returns')
        return [(failed, UNKNOWN), (state, UNKNOWN)]

    def run(self, operations, states):
        for op in operations:
            following = []
            for state in states:
                if state.exit != 'normal': following.append(state); continue
                self.steps += 1
                if self.steps > self.max_steps:
                    self.gap('step-budget', op.node, 'Analysis step budget reached; remaining execution omitted.')
                    state.exit = 'unmeasured'; following.append(state); continue
                following.extend(self.step(op, state))
            states = self.bound(following, op.node)
        return states

    def step(self, op, state):
        if op.kind == 'branch':
            # Calls in guards are evaluated before choosing the branch.
            results = self.evaluate(op.expr, state) if self.contains_call(op.expr) else [(state, UNKNOWN)]
            output = []
            for current, _ in results:
                if current.exit != 'normal': output.append(current); continue
                truth = self.truth(op.expr, current)
                for take in ([truth] if truth is not None else [True, False]):
                    branch = deepcopy(current)
                    guard = {'line': op.node.start_point.row + 1, 'condition': self.syntax.text(op.expr)[:160], 'taken': take}
                    branch.guards_truncated |= len(branch.guards) >= 16
                    branch.guards = (branch.guards + [guard])[-16:]
                    name = self.syntax.name(op.expr)
                    if name: branch.constraints[name] = take
                    self.mark(branch, op.node, 'branch ' + str(take))
                    output.extend(self.run(op.body if take else op.other, [branch]))
            return output
        if op.kind == 'try': return self.try_paths(op, state)
        if op.kind == 'unknown':
            state.values.clear(); state.constraints.clear()
            for resource in state.resources.values(): resource['state'] = 'escaped'
            return [state]
        output = []
        for current, value in self.evaluate(op.expr, state):
            if current.exit != 'normal': output.append(current); continue
            if op.kind == 'assign':
                before = current.values.get(op.target, UNKNOWN)
                self.transition(op.target, before, value, op.node, current)
                current.values[op.target] = value
                current.constraints.pop(op.target, None)
                if isinstance(value, tuple) and value and value[0] == 'resource':
                    current.resources[value[1]]['owner'] = op.target
                self.mark(current, op.node, op.target + ' assigned')
            if op.kind in {'return', 'throw'}:
                current.exit = op.kind
                if op.kind == 'return': current.returned = value
                self.mark(current, op.node, op.kind)
            output.append(current)
        return output

    def contains_call(self, node):
        if node is None: return False
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in {'call', 'call_expression', 'await', 'await_expression'}: return True
            stack.extend(current.named_children)
        return False

    def try_paths(self, op, state):
        body = self.run(op.body, [state]); handled = []
        for current in body:
            if current.exit == 'throw' and op.handlers:
                if not op.catches_all: handled.append(deepcopy(current))
                for handler in op.handlers:
                    caught = deepcopy(current); caught.exit = 'normal'
                    handled.extend(self.run(handler, [caught]))
            elif current.exit == 'normal': handled.extend(self.run(op.other, [current]))
            else: handled.append(current)
        output = []
        for current in self.bound(handled, op.node):
            previous = current.exit
            current.exit = 'normal'
            for final in self.run(op.final, [current]):
                if final.exit == 'normal': final.exit = previous
                elif previous in {'throw', 'return'} and final.exit != 'unmeasured':
                    self.finding('cleanup-overrides-exit', op.node,
                                 'Finally can replace a pending ' + previous + ' with ' + final.exit + '.', final)
                output.append(final)
        return self.bound(output, op.node)

    def analyze_scope(self, node, scope):
        self.scope = scope
        self.scope_id = node.start_byte
        # Duplicate lexical declarations would otherwise merge different JS bindings.
        names = set(); stack = [node]
        while stack:
            item = stack.pop()
            if item is not node and item.type in FUNCTIONS: continue
            if item.type == 'variable_declarator':
                name = self.syntax.name(item.child_by_field_name('name'))
                if name in names:
                    self.gap('shadowed-binding', item, 'Repeated lexical binding; this scope is skipped to preserve identity.')
                    return
                names.add(name)
            stack.extend(reversed(item.named_children))
        operations = self.syntax.lower(node)
        for state in self.run(operations, [PathState()]):
            returned = state.returned
            if state.exit == 'return' and isinstance(returned, tuple) and returned and returned[0] == 'resource':
                resource = state.resources[returned[1]]
                if resource['state'] == 'released':
                    self.finding('resource-return-released', resource['node'], 'Return delivers a handle already released by cleanup.', state, resource['owner'])
                elif resource['state'] == 'owned': resource['state'] = 'transferred'
            for resource in state.resources.values():
                if resource['state'] == 'owned' and state.exit != 'unmeasured':
                    self.finding('resource-unreleased', resource['node'],
                                 'Owned handle reaches ' + state.exit + ' exit without a successful release or transfer.',
                                 state, resource['owner'])
                if resource['state'] == 'release-unknown':
                    self.gap('release-outcome', resource['node'], 'A close failure leaves resource release uncertain.')

    def analyze(self, root):
        self.analyze_scope(root, '<module>')
        stack = list(reversed(root.named_children)); count = 0
        while stack:
            node = stack.pop()
            if node.type in FUNCTIONS:
                count += 1
                if count > 128:
                    self.gap('scope-budget', node, 'Only the first 128 function scopes are analysed.'); break
                name = node.child_by_field_name('name')
                scope = self.syntax.text(name) or '<anonymous@' + str(node.start_point.row + 1) + '>'
                body = node.child_by_field_name('body')
                if body: self.analyze_scope(body, scope)
            stack.extend(reversed(node.named_children))
        candidates = [c for c in self.candidates.values() if len(c['states']) > 1]
        entries = self.entries + candidates
        if len(entries) >= 1000:
            entries = entries[:999] + [{'category': 'gap', 'rule': 'entry-budget', 'scope': '<file>',
                'owner': '', 'location': self.location(root), 'detail': 'Entry budget reached; remaining entries omitted.'}]
        return sorted(entries, key=lambda e: (e['location']['start_byte'], e['category'], e['rule'], e['scope'], e['owner']))


def analyze(raw, root, language, max_paths=64):
    checker = Checker(raw, language, max_paths)
    stack = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > 120:
            checker.gap('syntax-depth', node, 'Syntax depth exceeds 120; this file is skipped.')
            return checker.entries
        stack.extend((child, depth + 1) for child in node.named_children)
    return checker.analyze(root)
