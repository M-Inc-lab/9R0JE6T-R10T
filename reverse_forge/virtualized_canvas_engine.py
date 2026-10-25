"""
R3V3R53//F0RG3 — Phase 56: High-Performance Virtualized Workbench Canvas & Quadtree Engine
Solves DOM degradation on massive control-flow and call graphs (>10,000 nodes) by providing:
  1. 2D Spatial Quadtree Index (`QuadtreeNode`) for $O(\\log N)$ viewport frustum culling
  2. Multi-Level of Detail (LOD) node serializer:
     - High Zoom (`scale >= 0.75`): Full instruction disassembly, mnemonics, and operand colors
     - Medium Zoom (`0.35 <= scale < 0.75`): Function/block header + call targets only
     - Low Zoom (`scale < 0.35`): Heatmap semantic bounding boxes colored by cyclomatic complexity
  3. HTML5 Canvas / WebGL 60fps Viewport & Minimap Generator
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class GraphNodeBox:
    node_id: int
    label: str
    x: float
    y: float
    width: float
    height: float
    complexity_heat: float = 0.2
    instructions: List[str] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


@dataclass
class ViewportBox:
    x: float
    y: float
    width: float
    height: float
    zoom_scale: float = 1.0

    def intersects(self, node: GraphNodeBox) -> bool:
        return not (
            node.x + node.width < self.x
            or node.x > self.x + self.width
            or node.y + node.height < self.y
            or node.y > self.y + self.height
        )


class SpatialQuadtree:
    """
    2D Quadtree spatial index for fast viewport frustum culling on large binary CFGs.
    """

    def __init__(self, bounds: ViewportBox, capacity: int = 8, depth: int = 0, max_depth: int = 6):
        self.bounds = bounds
        self.capacity = capacity
        self.depth = depth
        self.max_depth = max_depth
        self.nodes: List[GraphNodeBox] = []
        self.divided = False
        self.nw: Optional["SpatialQuadtree"] = None
        self.ne: Optional["SpatialQuadtree"] = None
        self.sw: Optional["SpatialQuadtree"] = None
        self.se: Optional["SpatialQuadtree"] = None

    def _subdivide(self) -> None:
        x, y, w, h = self.bounds.x, self.bounds.y, self.bounds.width / 2.0, self.bounds.height / 2.0
        self.nw = SpatialQuadtree(ViewportBox(x, y, w, h), self.capacity, self.depth + 1, self.max_depth)
        self.ne = SpatialQuadtree(ViewportBox(x + w, y, w, h), self.capacity, self.depth + 1, self.max_depth)
        self.sw = SpatialQuadtree(ViewportBox(x, y + h, w, h), self.capacity, self.depth + 1, self.max_depth)
        self.se = SpatialQuadtree(ViewportBox(x + w, y + h, w, h), self.capacity, self.depth + 1, self.max_depth)
        self.divided = True

    def insert(self, node: GraphNodeBox) -> bool:
        if not self.bounds.intersects(node):
            return False
        if len(self.nodes) < self.capacity or self.depth >= self.max_depth:
            self.nodes.append(node)
            return True
        if not self.divided:
            self._subdivide()
        assert self.nw and self.ne and self.sw and self.se
        self.nw.insert(node)
        self.ne.insert(node)
        self.sw.insert(node)
        self.se.insert(node)
        return True

    def query_viewport(self, viewport: ViewportBox) -> List[GraphNodeBox]:
        if not self.bounds.intersects(
            GraphNodeBox(-1, "", viewport.x, viewport.y, viewport.width, viewport.height)
        ):
            return []

        found: Dict[int, GraphNodeBox] = {}
        for n in self.nodes:
            if viewport.intersects(n):
                found[n.node_id] = n

        if self.divided:
            assert self.nw and self.ne and self.sw and self.se
            for child in (self.nw, self.ne, self.sw, self.se):
                for n in child.query_viewport(viewport):
                    found[n.node_id] = n

        return [found[k] for k in sorted(found.keys())]


class VirtualizedCanvasEngine:
    """
    Manages quadtree spatial culling and Multi-Level-of-Detail (LOD) serialization
    for 60fps HTML5 Canvas / WebGL rendering.
    """

    def __init__(self, world_width: float = 100000.0, world_height: float = 100000.0):
        self.world_bounds = ViewportBox(0.0, 0.0, world_width, world_height)
        self.quadtree = SpatialQuadtree(self.world_bounds)
        self.all_nodes: Dict[int, GraphNodeBox] = {}

    def add_node(self, node: GraphNodeBox) -> None:
        self.all_nodes[node.node_id] = node
        self.quadtree.insert(node)

    @staticmethod
    def classify_lod_mode(zoom_scale: float) -> str:
        if zoom_scale >= 0.75:
            return "LOD_HIGH_FULL_DISASM"
        if zoom_scale >= 0.35:
            return "LOD_MEDIUM_HEADERS_ONLY"
        return "LOD_LOW_HEATMAP_BLOCKS"

    def render_viewport_frame(self, viewport: ViewportBox) -> Dict[str, Any]:
        """
        Return only the visible nodes inside `viewport` formatted according to the
        active zoom Level-of-Detail (LOD), plus minimap coordinates.
        """
        visible = self.quadtree.query_viewport(viewport)
        lod_mode = self.classify_lod_mode(viewport.zoom_scale)

        rendered_nodes: List[Dict[str, Any]] = []
        for n in visible:
            if lod_mode == "LOD_HIGH_FULL_DISASM":
                rendered_nodes.append(asdict(n))
            elif lod_mode == "LOD_MEDIUM_HEADERS_ONLY":
                rendered_nodes.append({
                    "node_id": n.node_id,
                    "label": n.label,
                    "x": n.x, "y": n.y, "width": n.width, "height": n.height,
                    "complexity_heat": n.complexity_heat,
                    "instructions": n.instructions[:1],
                    "successors": n.successors,
                })
            else:
                rendered_nodes.append({
                    "node_id": n.node_id,
                    "label": n.label,
                    "x": n.x, "y": n.y, "width": n.width, "height": n.height,
                    "complexity_heat": n.complexity_heat,
                    "instructions": [],
                    "successors": [],
                })

        return {
            "total_graph_nodes": len(self.all_nodes),
            "visible_culled_nodes_count": len(rendered_nodes),
            "lod_mode": lod_mode,
            "renderer_backend": "WEBGL_INSTANCED" if len(self.all_nodes) > 2500 else "HTML5_CANVAS_2D",
            "minimap_rect": {
                "norm_x": round(viewport.x / max(1.0, self.world_bounds.width), 4),
                "norm_y": round(viewport.y / max(1.0, self.world_bounds.height), 4),
                "norm_w": round(viewport.width / max(1.0, self.world_bounds.width), 4),
                "norm_h": round(viewport.height / max(1.0, self.world_bounds.height), 4),
            },
            "nodes": rendered_nodes,
        }
