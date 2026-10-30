from __future__ import annotations

from dataclasses import dataclass
import heapq
from collections import deque


NODES = (
    "PC-Contabilidad",
    "Switch-Piso1",
    "Servidor-Archivos",
    "Firewall-Interno",
    "Switch-Piso2",
    "AP-WiFi-Invitados",
    "Servidor-Financiero",
)

EDGES = (
    ("PC-Contabilidad", "Switch-Piso1", 1),
    ("Switch-Piso1", "Servidor-Archivos", 3),
    ("Servidor-Archivos", "Servidor-Financiero", 5),
    ("Switch-Piso1", "Firewall-Interno", 4),
    ("Firewall-Interno", "Servidor-Financiero", 1),
    ("Switch-Piso1", "Switch-Piso2", 2),
    ("Switch-Piso2", "Servidor-Financiero", 2),
    ("Switch-Piso1", "AP-WiFi-Invitados", 6),
)

HEURISTIC = {
    "PC-Contabilidad": 3,
    "Switch-Piso1": 2,
    "Servidor-Archivos": 1,
    "Firewall-Interno": 1,
    "Switch-Piso2": 1,
    "AP-WiFi-Invitados": 3,
    "Servidor-Financiero": 0,
}


@dataclass(frozen=True)
class SearchResult:
    algorithm: str
    path: tuple[str, ...]
    cost: int
    expanded: tuple[str, ...]


def _graph():
    graph = {node: [] for node in NODES}
    for left, right, cost in EDGES:
        graph[left].append((right, cost))
        graph[right].append((left, cost))
    return graph


def _result(name, parents, goal, expanded, costs):
    if goal not in parents:
        return SearchResult(name, (), 0, tuple(expanded))
    path = []
    current = goal
    while current is not None:
        path.append(current)
        current = parents[current]
    path.reverse()
    return SearchResult(name, tuple(path), costs[goal], tuple(expanded))


def breadth_first(start, goal):
    graph = _graph(); queue = deque([start]); parents = {start: None}; expanded = []
    while queue:
        current = queue.popleft()
        if current == goal: break
        expanded.append(current)
        for neighbor, _ in graph[current]:
            if neighbor not in parents:
                parents[neighbor] = current; queue.append(neighbor)
    costs = {node: 0 for node in parents}
    for left, right, cost in EDGES:
        if parents.get(right) == left: costs[right] = costs[left] + cost
        if parents.get(left) == right: costs[left] = costs[right] + cost
    return _result("BFS", parents, goal, expanded, costs)


def depth_first(start, goal):
    graph = _graph(); stack = [start]; parents = {start: None}; expanded = []
    while stack:
        current = stack.pop()
        if current == goal: break
        expanded.append(current)
        for neighbor, _ in graph[current]:
            if neighbor not in parents:
                parents[neighbor] = current; stack.append(neighbor)
    costs = {node: 0 for node in parents}
    for node in parents:
        if node == start: continue
        parent = parents[node]
        costs[node] = costs[parent] + next(cost for neighbor, cost in graph[parent] if neighbor == node)
    return _result("DFS", parents, goal, expanded, costs)


def uniform_cost(start, goal):
    graph = _graph(); frontier = [(0, 0, start)]; sequence = 0
    parents = {start: None}; costs = {start: 0}; expanded = []
    while frontier:
        cost, _, current = heapq.heappop(frontier)
        if cost != costs[current]: continue
        if current == goal: break
        expanded.append(current)
        for neighbor, edge_cost in graph[current]:
            new_cost = cost + edge_cost
            if new_cost < costs.get(neighbor, float("inf")):
                sequence += 1; costs[neighbor] = new_cost; parents[neighbor] = current
                heapq.heappush(frontier, (new_cost, sequence, neighbor))
    return _result("UCS", parents, goal, expanded, costs)


def greedy(start, goal):
    graph = _graph(); frontier = [(HEURISTIC[start], 0, start)]; sequence = 0
    parents = {start: None}; expanded = []; costs = {start: 0}
    while frontier:
        _, _, current = heapq.heappop(frontier)
        if current == goal: break
        expanded.append(current)
        for neighbor, edge_cost in graph[current]:
            if neighbor not in parents:
                sequence += 1; parents[neighbor] = current; costs[neighbor] = costs[current] + edge_cost
                heapq.heappush(frontier, (HEURISTIC[neighbor], sequence, neighbor))
    return _result("Greedy", parents, goal, expanded, costs)


def a_star(start, goal):
    graph = _graph(); frontier = [(HEURISTIC[start], 0, start)]; sequence = 0
    parents = {start: None}; costs = {start: 0}; expanded = []
    while frontier:
        _, _, current = heapq.heappop(frontier)
        if current == goal: break
        expanded.append(current)
        for neighbor, edge_cost in graph[current]:
            new_cost = costs[current] + edge_cost
            if new_cost < costs.get(neighbor, float("inf")):
                sequence += 1; costs[neighbor] = new_cost; parents[neighbor] = current
                heapq.heappush(frontier, (new_cost + HEURISTIC[neighbor], sequence, neighbor))
    return _result("A*", parents, goal, expanded, costs)


SEARCH_METHODS = {
    "BFS": breadth_first,
    "DFS": depth_first,
    "UCS": uniform_cost,
    "Greedy": greedy,
    "A*": a_star,
}


def search(method, start="PC-Contabilidad", goal="Servidor-Financiero"):
    return SEARCH_METHODS[method](start, goal)