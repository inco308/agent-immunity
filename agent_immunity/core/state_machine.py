"""显式策略状态；自然语言描述不参与授权。"""
class SessionState:
    def __init__(self, transitions):
        self.transitions = transitions
        self.current = "START"
        self.completed_count = 0

    def allows(self, target):
        return not self.transitions or target in self.transitions.get(self.current, ())

    def commit(self, target):
        self.current = target
        self.completed_count += 1
