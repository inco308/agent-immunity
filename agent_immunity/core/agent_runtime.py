"""显式依赖图实验模块，不推断因果关系或承诺模型自愈。"""
from dataclasses import dataclass, field

@dataclass
class ActionNode:
    node_id: str
    parents: frozenset[str] = field(default_factory=frozenset)

class CausalActionDAG:
    def __init__(self):
        self.nodes = {}

    def add_node(self, node_id, parent_ids=()):
        if node_id in self.nodes or node_id in parent_ids or any(p not in self.nodes for p in parent_ids):
            raise ValueError("节点重复或依赖不存在")
        # 仅允许引用已存在节点，避免引入环。
        self.nodes[node_id] = ActionNode(node_id, frozenset(parent_ids))

    def prune(self, roots, pending_ids):
        if not set(roots) <= self.nodes.keys() or not set(pending_ids) <= self.nodes.keys():
            raise ValueError("未知节点")
        affected = set(roots)
        for node in self.nodes.values():
            if node.parents & affected:
                affected.add(node.node_id)
        return [node_id for node_id in pending_ids if node_id not in affected]
