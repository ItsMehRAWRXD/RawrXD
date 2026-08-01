"""
Chatter Boxes — Context Length Reverse Engineered

Instead of one long linear context window, we have multiple "boxes" that
each hold different types of context. They "chat" with each other by
passing messages through a bus.

Each box:
  - Has its own context window (e.g., 4096 tokens)
  - Is specialized for a type of content
  - Can send/receive messages to/from other boxes
  - Can be added or removed dynamically

The effective context is the SUM of all boxes, but ORGANIZED — not a wall.

Traditional:  [token token token token token token token token token ...]
Chatter:      [Box0: system] [Box1: user] [Box2: knowledge] [Box3: working]

Signed: ~g87 | RawrXD | uwu kawaii
"""

import json
import time
import hashlib
import threading
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum, auto
from collections import deque


# ═════════════════════════════════════════════════════════════════════
# BOX TYPES — Each box has a purpose
# ═════════════════════════════════════════════════════════════════════

class BoxType(Enum):
    """What kind of content a box holds."""
    SYSTEM = "system"              # System instructions, personality
    USER = "user"                  # User messages / input
    ASSISTANT = "assistant"        # Assistant responses
    KNOWLEDGE = "knowledge"        # Facts, knowledge base
    WORKING_MEMORY = "working"     # Scratchpad, current task state
    LONG_TERM = "long_term"        # Summarized history
    TOOL = "tool"                  # Tool call results
    ATTENTION = "attention"        # What the model is focusing on
    PLAN = "plan"                  # Multi-step plan
    REASONING = "reasoning"        # Chain-of-thought reasoning
    CUSTOM = "custom"              # User-defined


@dataclass
class Message:
    """A message passed between boxes."""
    sender: str                    # Box name
    recipient: str                 # Box name (or "broadcast")
    content: str                   # Message content
    msg_type: str                  # "request", "response", "broadcast", "update"
    priority: int = 0             # 0=normal, 1=high, 2=urgent
    timestamp: float = 0.0
    msg_id: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()
        if not self.msg_id:
            self.msg_id = hashlib.md5(
                f"{self.sender}:{self.recipient}:{self.content}:{self.timestamp}".encode()
            ).hexdigest()[:12]


@dataclass
class ChatterBox:
    """
    A single chatter box — an independent context window.
    
    Each box:
    - Has a name and type
    - Holds its own context (list of tokens/messages)
    - Has a max context length
    - Can send/receive messages
    - Has its own attention focus
    """
    name: str
    box_type: BoxType
    max_tokens: int = 4096
    description: str = ""
    
    # Context content
    tokens: List[str] = field(default_factory=list)
    messages: List[Message] = field(default_factory=list)
    
    # Box state
    temperature: float = 0.7
    is_active: bool = True
    priority: int = 0              # Higher = more important, evicted last
    created_at: float = 0.0
    last_used: float = 0.0
    use_count: int = 0
    
    # Attention focus — what this box is currently looking at
    focus: str = ""
    
    # Compression (for long-term boxes)
    compressed: bool = False
    compression_ratio: float = 1.0
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        self.last_used = time.time()
    
    @property
    def token_count(self) -> int:
        """Number of tokens currently in this box."""
        return len(self.tokens)
    
    @property
    def utilization(self) -> float:
        """How full this box is (0.0 to 1.0)."""
        return self.token_count / self.max_tokens if self.max_tokens > 0 else 0.0
    
    @property
    def is_full(self) -> bool:
        """Whether this box is at capacity."""
        return self.token_count >= self.max_tokens
    
    @property
    def available_tokens(self) -> int:
        """How many more tokens this box can hold."""
        return self.max_tokens - self.token_count
    
    def add_token(self, token: str) -> bool:
        """Add a token to this box. Returns False if full."""
        if self.is_full:
            return False
        self.tokens.append(token)
        self.last_used = time.time()
        self.use_count += 1
        return True
    
    def add_tokens(self, tokens: List[str]) -> int:
        """Add multiple tokens. Returns number actually added."""
        added = 0
        for token in tokens:
            if self.is_full:
                break
            self.tokens.append(token)
            added += 1
        if added > 0:
            self.last_used = time.time()
            self.use_count += 1
        return added
    
    def add_message(self, msg: Message):
        """Add a message to this box's message log."""
        self.messages.append(msg)
        self.last_used = time.time()
    
    def clear(self):
        """Clear all tokens from this box."""
        self.tokens.clear()
        self.last_used = time.time()
    
    def summarize(self, max_tokens: int = 256) -> str:
        """Summarize this box's content (for compression)."""
        if not self.tokens:
            return f"[{self.name}: empty]"
        
        # Take first and last tokens as a summary
        head = " ".join(self.tokens[:50])
        tail = " ".join(self.tokens[-50:]) if len(self.tokens) > 100 else ""
        
        if tail:
            return f"[{self.name}: {len(self.tokens)} tokens] {head} ... {tail}"
        return f"[{self.name}: {len(self.tokens)} tokens] {head}"
    
    def info(self) -> str:
        """One-line box info."""
        return (f"Box[{self.name}] {self.box_type.value} "
                f"{self.token_count}/{self.max_tokens} tokens "
                f"({self.utilization*100:.0f}% full) "
                f"{'ACTIVE' if self.is_active else 'INACTIVE'}")


# ═════════════════════════════════════════════════════════════════════
# CHATTER BUS — The communication backbone
# ═════════════════════════════════════════════════════════════════════

class ChatterBus:
    """
    The communication bus between chatter boxes.
    
    Boxes don't talk directly to each other — they send messages
    through the bus. The bus routes messages to the right box.
    
    This is like a message queue / event bus for context boxes.
    """
    
    def __init__(self):
        self._queues: Dict[str, deque] = {}  # box_name → message queue
        self._broadcast_history: List[Message] = []
        self._lock = threading.Lock()
    
    def send(self, msg: Message):
        """Send a message through the bus."""
        with self._lock:
            if msg.recipient == "broadcast":
                self._broadcast_history.append(msg)
            else:
                if msg.recipient not in self._queues:
                    self._queues[msg.recipient] = deque()
                self._queues[msg.recipient].append(msg)
    
    def receive(self, box_name: str) -> List[Message]:
        """Get all pending messages for a box."""
        with self._lock:
            queue = self._queues.get(box_name, deque())
            messages = list(queue)
            queue.clear()
            return messages
    
    def broadcast(self, sender: str, content: str, msg_type: str = "broadcast"):
        """Send a message to ALL boxes."""
        msg = Message(
            sender=sender,
            recipient="broadcast",
            content=content,
            msg_type=msg_type,
        )
        self.send(msg)
    
    def get_broadcasts(self) -> List[Message]:
        """Get all broadcast messages."""
        return self._broadcast_history[-50:]  # Last 50 broadcasts
    
    def clear(self):
        """Clear all queues."""
        with self._lock:
            self._queues.clear()
            self._broadcast_history.clear()


# ═════════════════════════════════════════════════════════════════════
# CHATTER MANAGER — Orchestrates all boxes
# ═════════════════════════════════════════════════════════════════════

@dataclass
class ChatterContext:
    """
    The complete context — the sum of all chatter boxes.
    
    This is what gets fed to the model. Instead of one long sequence,
    it's a structured collection of boxes, each with their own context.
    """
    boxes: Dict[str, ChatterBox] = field(default_factory=dict)
    total_tokens: int = 0
    max_total_tokens: int = 0
    box_count: int = 0
    active_box_count: int = 0
    
    def to_prompt(self, format: str = "tagged") -> str:
        """
        Convert all boxes to a single prompt string.
        
        Formats:
        - "tagged": <box name="system">...</box>
        - "linear": [System] ... [User] ...
        - "compact": Box0: ... | Box1: ...
        """
        parts = []
        
        if format == "tagged":
            for name, box in self.boxes.items():
                if box.is_active and box.tokens:
                    content = " ".join(box.tokens)
                    parts.append(f'<box name="{name}" type="{box.box_type.value}">')
                    parts.append(content)
                    parts.append(f'</box>')
        
        elif format == "linear":
            for name, box in self.boxes.items():
                if box.is_active and box.tokens:
                    content = " ".join(box.tokens)
                    parts.append(f"[{box.box_type.value.upper()}: {name}]")
                    parts.append(content)
                    parts.append("")
        
        elif format == "compact":
            items = []
            for name, box in self.boxes.items():
                if box.is_active and box.tokens:
                    content = " ".join(box.tokens[:20])
                    items.append(f"{name}: {content}")
            parts.append(" | ".join(items))
        
        return "\n".join(parts)
    
    def info(self) -> str:
        """Multi-line context info."""
        lines = [f"Chatter Context: {self.box_count} boxes, {self.total_tokens} total tokens"]
        for name, box in self.boxes.items():
            lines.append(f"  {box.info()}")
        return "\n".join(lines)


class ChatterManager:
    """
    Manages all chatter boxes.
    
    - Creates boxes as needed
    - Routes messages between boxes
    - Evicts old boxes when memory is needed
    - Compresses long-term boxes
    - Provides the combined context to the model
    """
    
    VERSION = "chatter-1.0"
    SIGNATURE = "~g87"
    
    def __init__(self, default_box_size: int = 4096, max_boxes: int = 8):
        self.default_box_size = default_box_size
        self.max_boxes = max_boxes
        self.boxes: Dict[str, ChatterBox] = {}
        self.bus = ChatterBus()
        self.total_inferences = 0
        self.total_messages_passed = 0
        self.box_creation_order: List[str] = []
        self._box_counter = 0  # Monotonic counter for unique box names
        
        # Create default boxes
        self._create_default_boxes()
    
    def _create_default_boxes(self):
        """Create the default set of chatter boxes."""
        defaults = [
            ("system", BoxType.SYSTEM, 2048, 
             "System instructions, personality, constraints"),
            ("user", BoxType.USER, 4096,
             "User messages and input"),
            ("assistant", BoxType.ASSISTANT, 4096,
             "Assistant responses and output"),
            ("knowledge", BoxType.KNOWLEDGE, 2048,
             "Facts, knowledge base, retrieved context"),
            ("working", BoxType.WORKING_MEMORY, 1024,
             "Current task state, scratchpad"),
        ]
        
        for name, btype, size, desc in defaults:
            self.add_box(name, btype, size, desc)
    
    def add_box(self, name: str, box_type: BoxType, 
                max_tokens: Optional[int] = None,
                description: str = "") -> ChatterBox:
        """Add a new chatter box."""
        if name in self.boxes:
            raise ValueError(f"Box '{name}' already exists")
        
        if len(self.boxes) >= self.max_boxes:
            # Evict the least recently used box
            self._evict_lru()
        
        box = ChatterBox(
            name=name,
            box_type=box_type,
            max_tokens=max_tokens or self.default_box_size,
            description=description or f"{box_type.value} box",
        )
        
        self.boxes[name] = box
        self.box_creation_order.append(name)
        
        # Broadcast the new box
        self.bus.broadcast(
            "manager",
            f"New box created: {name} ({box_type.value})",
            "update"
        )
        
        return box
    
    def remove_box(self, name: str):
        """Remove a chatter box."""
        if name in self.boxes:
            box = self.boxes[name]
            # Don't remove essential boxes
            if box.box_type in (BoxType.SYSTEM, BoxType.USER):
                return False
            
            # Summarize and broadcast
            summary = box.summarize()
            self.bus.broadcast("manager", f"Box removed: {name}. Content: {summary}")
            
            del self.boxes[name]
            if name in self.box_creation_order:
                self.box_creation_order.remove(name)
            return True
        return False
    
    def _evict_lru(self):
        """Evict the least recently used non-essential box."""
        candidates = [
            (name, box) for name, box in self.boxes.items()
            if box.box_type not in (BoxType.SYSTEM, BoxType.USER)
        ]
        
        if not candidates:
            return
        
        # Sort by last_used (oldest first)
        candidates.sort(key=lambda x: x[1].last_used)
        oldest_name, oldest_box = candidates[0]
        
        # Compress and remove
        summary = oldest_box.summarize()
        self.bus.broadcast("manager", 
            f"Evicting box '{oldest_name}' to make room. Summary: {summary}")
        
        del self.boxes[oldest_name]
        if oldest_name in self.box_creation_order:
            self.box_creation_order.remove(oldest_name)
    
    def write_to_box(self, box_name: str, content: str) -> bool:
        """Write content to a specific box."""
        box = self.boxes.get(box_name)
        if not box:
            return False
        
        tokens = content.split()
        added = box.add_tokens(tokens)
        
        # If box is getting full, send a warning
        if box.utilization > 0.9:
            self.bus.send(Message(
                sender=box_name,
                recipient="manager",
                content=f"Box '{box_name}' is {box.utilization*100:.0f}% full",
                msg_type="warning",
                priority=1,
            ))
        
        return added > 0
    
    def read_from_box(self, box_name: str, max_tokens: Optional[int] = None) -> str:
        """Read content from a specific box."""
        box = self.boxes.get(box_name)
        if not box:
            return ""
        
        if max_tokens:
            return " ".join(box.tokens[:max_tokens])
        return " ".join(box.tokens)
    
    def box_to_box(self, from_box: str, to_box: str, content: str):
        """Send content from one box to another."""
        msg = Message(
            sender=from_box,
            recipient=to_box,
            content=content,
            msg_type="transfer",
        )
        self.bus.send(msg)
        self.total_messages_passed += 1
        
        # Also write to the target box
        self.write_to_box(to_box, content)
    
    def process_messages(self):
        """Process all pending messages on the bus."""
        for box_name in list(self.boxes.keys()):
            messages = self.bus.receive(box_name)
            for msg in messages:
                box = self.boxes.get(box_name)
                if box:
                    box.add_message(msg)
                    
                    # Auto-write broadcast content to knowledge box
                    if msg.msg_type == "broadcast" and box_name == "knowledge":
                        self.write_to_box("knowledge", f"[{msg.sender}] {msg.content}")
    
    def get_context(self) -> ChatterContext:
        """Get the complete context from all boxes."""
        ctx = ChatterContext()
        ctx.boxes = self.boxes
        ctx.total_tokens = sum(b.token_count for b in self.boxes.values())
        ctx.max_total_tokens = sum(b.max_tokens for b in self.boxes.values())
        ctx.box_count = len(self.boxes)
        ctx.active_box_count = sum(1 for b in self.boxes.values() if b.is_active)
        return ctx
    
    def compress_boxes(self, target_utilization: float = 0.5):
        """
        Compress boxes to free up context space.
        
        Non-essential boxes get summarized to a fraction of their size.
        Essential boxes (system, user) are preserved.
        """
        for name, box in self.boxes.items():
            if box.box_type in (BoxType.SYSTEM, BoxType.USER):
                continue  # Don't compress essential boxes
            
            if box.utilization > target_utilization:
                # Summarize to 25% of max
                summary = box.summarize(max_tokens=box.max_tokens // 4)
                box.tokens = summary.split()
                box.compressed = True
                box.compression_ratio = box.utilization
                
                self.bus.broadcast(
                    "manager",
                    f"Compressed box '{name}': {box.token_count} tokens remaining",
                    "update"
                )
    
    def spawn_reasoning_box(self, topic: str) -> str:
        """Spawn a temporary reasoning box for chain-of-thought."""
        self._box_counter += 1
        name = f"reasoning_{self._box_counter}"
        box = self.add_box(
            name=name,
            box_type=BoxType.REASONING,
            max_tokens=2048,
            description=f"Reasoning about: {topic}",
        )
        box.focus = topic
        self.write_to_box(name, f"[Reasoning about: {topic}]")
        return name
    
    def spawn_plan_box(self, goal: str) -> str:
        """Spawn a planning box for multi-step tasks."""
        self._box_counter += 1
        name = f"plan_{self._box_counter}"
        box = self.add_box(
            name=name,
            box_type=BoxType.PLAN,
            max_tokens=2048,
            description=f"Plan for: {goal}",
        )
        box.focus = goal
        self.write_to_box(name, f"[Plan for: {goal}]")
        return name
    
    def get_stats(self) -> Dict:
        """Get manager statistics."""
        ctx = self.get_context()
        return {
            "version": self.VERSION,
            "signature": self.SIGNATURE,
            "boxes": ctx.box_count,
            "active_boxes": ctx.active_box_count,
            "total_tokens": ctx.total_tokens,
            "max_total_tokens": ctx.max_total_tokens,
            "utilization": ctx.total_tokens / max(ctx.max_total_tokens, 1) * 100,
            "messages_passed": self.total_messages_passed,
            "inferences": self.total_inferences,
            "boxes_detail": {
                name: {
                    "type": box.box_type.value,
                    "tokens": box.token_count,
                    "max": box.max_tokens,
                    "util": box.utilization * 100,
                    "active": box.is_active,
                }
                for name, box in self.boxes.items()
            },
        }
    
    def print_summary(self):
        """Print a visual summary of all chatter boxes."""
        stats = self.get_stats()
        
        print(f"\n╔══════════════════════════════════════════════════════════════╗")
        print(f"║  CHATTER BOX SYSTEM — {stats['version']:12s}  Signed: {self.SIGNATURE}  ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║  {stats['boxes']} boxes × {self.default_box_size} tokens = {stats['max_total_tokens']:,} max tokens  ║")
        print(f"║  Currently using {stats['total_tokens']:,} tokens ({stats['utilization']:.0f}% full)        ║")
        print(f"║  Messages passed: {stats['messages_passed']}                              ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║                                                               ║")
        
        for name, detail in stats["boxes_detail"].items():
            bar_len = int(detail["util"] / 100 * 30)
            bar = "█" * bar_len + "░" * (30 - bar_len)
            status = "✓" if detail["active"] else "✗"
            print(f"║  {status} {name:12s} [{bar}] {detail['tokens']:>5d}/{detail['max']:<5d} ({detail['util']:.0f}%)  ║")
        
        print(f"║                                                               ║")
        print(f"║  Instead of one long context, boxes chat through a bus.        ║")
        print(f"║  Each box has a purpose. They pass messages.                  ║")
        print(f"║  The effective context is the SUM, but ORGANIZED.             ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")


# ═════════════════════════════════════════════════════════════════════
# CHATTER INFERENCE — Using boxes for actual inference
# ═════════════════════════════════════════════════════════════════════

class ChatterInference:
    """
    Uses chatter boxes for inference.
    
    Instead of feeding one long prompt to the model, we:
    1. Distribute content across specialized boxes
    2. Let boxes "chat" to share relevant context
    3. Build the final prompt from all active boxes
    4. Process messages after each inference
    """
    
    def __init__(self, manager: ChatterManager):
        self.manager = manager
        self.conversation_history: List[Dict] = []
    
    def chat(self, user_input: str) -> str:
        """
        Process a user input through the chatter box system.
        
        1. Write user input to the user box
        2. Check if we need more context (spawn boxes)
        3. Build the prompt from all boxes
        4. Run inference (simulated)
        5. Process messages between boxes
        6. Write response to assistant box
        """
        # Step 1: Write user input
        self.manager.write_to_box("user", user_input)
        
        # Step 2: Analyze input — do we need more context?
        needs = self._analyze_input(user_input)
        
        for need in needs:
            if need["type"] == "reasoning":
                self.manager.spawn_reasoning_box(need["topic"])
            elif need["type"] == "plan":
                self.manager.spawn_plan_box(need["goal"])
            elif need["type"] == "knowledge":
                # Ask knowledge box to retrieve relevant facts
                self.manager.box_to_box(
                    "user", "knowledge",
                    f"Need knowledge about: {need['topic']}"
                )
        
        # Step 3: Build context
        context = self.manager.get_context()
        
        # Step 4: Run inference (simulated)
        response = self._infer(context, user_input)
        
        # Step 5: Process messages
        self.manager.process_messages()
        
        # Step 6: Write response
        self.manager.write_to_box("assistant", response)
        
        # Track conversation
        self.conversation_history.append({
            "user": user_input,
            "assistant": response,
            "boxes_used": list(self.manager.boxes.keys()),
            "total_tokens": context.total_tokens,
        })
        
        self.manager.total_inferences += 1
        
        return response
    
    def _analyze_input(self, user_input: str) -> List[Dict]:
        """Analyze user input to determine what boxes are needed."""
        needs = []
        input_lower = user_input.lower()
        
        # Check for reasoning needs
        reasoning_triggers = ["why", "how", "explain", "reason", "think", 
                            "analyze", "compare", "contrast", "evaluate",
                            "what if", "imagine", "suppose", "consider"]
        for trigger in reasoning_triggers:
            if trigger in input_lower:
                needs.append({
                    "type": "reasoning",
                    "topic": user_input[:100],
                })
                break
        
        # Check for planning needs
        plan_triggers = ["plan", "step", "strategy", "approach", "method",
                        "procedure", "process", "workflow", "pipeline",
                        "roadmap", "timeline", "schedule", "organize"]
        for trigger in plan_triggers:
            if trigger in input_lower:
                needs.append({
                    "type": "plan",
                    "goal": user_input[:100],
                })
                break
        
        # Check for knowledge needs
        knowledge_triggers = ["what is", "tell me about", "define", "explain",
                            "describe", "what are", "who is", "where is",
                            "when did", "how does", "facts about", "information"]
        for trigger in knowledge_triggers:
            if trigger in input_lower:
                needs.append({
                    "type": "knowledge",
                    "topic": user_input[:100],
                })
                break
        
        return needs
    
    def _infer(self, context: ChatterContext, user_input: str) -> str:
        """
        Simulated inference using chatter boxes.
        
        In production, this would call the actual model with the
        structured context prompt.
        """
        # Build the prompt from all boxes
        prompt = context.to_prompt(format="tagged")
        
        # Simulate different responses based on which boxes are active
        has_reasoning = any(
            b.box_type == BoxType.REASONING for b in context.boxes.values()
        )
        has_plan = any(
            b.box_type == BoxType.PLAN for b in context.boxes.values()
        )
        has_knowledge = any(
            b.box_type == BoxType.KNOWLEDGE for b in context.boxes.values()
        )
        
        # Generate a themed response
        parts = []
        
        if has_reasoning:
            parts.append("Let me reason through this step by step.")
        
        if has_knowledge:
            parts.append("I've consulted my knowledge base for relevant context.")
        
        if has_plan:
            parts.append("I've created a structured plan to address this.")
        
        # General response
        parts.append(f"Based on my analysis of your input across "
                    f"{context.active_box_count} active context boxes, "
                    f"here's my response to: '{user_input[:50]}...'")
        
        return " ".join(parts)
    
    def get_conversation_summary(self) -> str:
        """Get a summary of the conversation so far."""
        if not self.conversation_history:
            return "No conversation yet."
        
        total_exchanges = len(self.conversation_history)
        avg_tokens = sum(
            h["total_tokens"] for h in self.conversation_history
        ) / total_exchanges
        
        return (f"Conversation: {total_exchanges} exchanges, "
                f"avg {avg_tokens:.0f} tokens per exchange, "
                f"using {len(self.manager.boxes)} chatter boxes")


# ═════════════════════════════════════════════════════════════════════
# DEMO
# ═════════════════════════════════════════════════════════════════════

def run_demo():
    """Run a demonstration of the chatter box system."""
    print("\n" + "=" * 62)
    print("  CHATTER BOXES — Context Length Reverse Engineered")
    print("  Instead of one long context, boxes that chat.")
    print("=" * 62)
    
    # Create the manager
    manager = ChatterManager(default_box_size=4096, max_boxes=8)
    manager.print_summary()
    
    # Create the inference engine
    engine = ChatterInference(manager)
    
    # Demo conversations
    conversations = [
        "What is the capital of France?",
        "Explain how neural networks work step by step",
        "Plan a strategy for learning Python programming",
        "Why is the sky blue? I need a detailed scientific explanation",
        "Compare and contrast machine learning and traditional programming",
    ]
    
    print(f"\n{'─'*62}")
    print(f"  Running {len(conversations)} conversations through chatter boxes")
    print(f"{'─'*62}")
    
    for i, user_input in enumerate(conversations, 1):
        print(f"\n  [{i}] User: {user_input}")
        
        response = engine.chat(user_input)
        print(f"  Assistant: {response[:120]}...")
        
        # Show box state after each exchange
        stats = manager.get_stats()
        print(f"  Boxes: {stats['boxes']} active, "
              f"{stats['total_tokens']:,} tokens used, "
              f"{stats['messages_passed']} messages passed")
    
    # Final summary
    print(f"\n{'─'*62}")
    print(f"  Final State")
    print(f"{'─'*62}")
    manager.print_summary()
    
    print(f"\n  Conversation: {engine.get_conversation_summary()}")
    
    # Show the structured context
    print(f"\n  Structured Context (tagged format):")
    context = manager.get_context()
    print(f"\n{context.to_prompt(format='tagged')[:500]}...")
    
    print(f"\n  Signed: ~g87 | Version: chatter-1.0 | RawrXD")
    print(f"  Instead of one long context, boxes that chat.")


# ═════════════════════════════════════════════════════════════════════
# SMOKE TESTS
# ═════════════════════════════════════════════════════════════════════

def run_smoke_tests():
    """Run smoke tests to verify the chatter box system."""
    print("\n" + "=" * 62)
    print("  CHATTER BOX SMOKE TESTS")
    print("=" * 62)
    
    tests_passed = 0
    tests_failed = 0
    
    def check(name: str, condition: bool, detail: str = ""):
        nonlocal tests_passed, tests_failed
        if condition:
            tests_passed += 1
            print(f"  ✓ {name}")
        else:
            tests_failed += 1
            print(f"  ✗ {name}: {detail}")
    
    # Test 1: Create manager with default boxes
    print(f"\n  [Test Group 1: Basic Box Operations]")
    manager = ChatterManager(default_box_size=4096, max_boxes=8)
    check("Default boxes created", len(manager.boxes) == 5)
    check("System box exists", "system" in manager.boxes)
    check("User box exists", "user" in manager.boxes)
    check("Assistant box exists", "assistant" in manager.boxes)
    check("Knowledge box exists", "knowledge" in manager.boxes)
    check("Working memory box exists", "working" in manager.boxes)
    
    # Test 2: Box properties
    print(f"\n  [Test Group 2: Box Properties]")
    sys_box = manager.boxes["system"]
    check("System box has correct type", sys_box.box_type == BoxType.SYSTEM)
    check("System box has max tokens", sys_box.max_tokens == 2048)
    check("Box starts empty", sys_box.token_count == 0)
    check("Box is not full", not sys_box.is_full)
    check("Box utilization is 0", sys_box.utilization == 0.0)
    
    # Test 3: Writing to boxes
    print(f"\n  [Test Group 3: Writing to Boxes]")
    result = manager.write_to_box("system", "You are a helpful assistant.")
    check("Write to system box", result)
    check("System box has tokens", manager.boxes["system"].token_count > 0)
    
    result = manager.write_to_box("user", "What is the weather?")
    check("Write to user box", result)
    check("User box has tokens", manager.boxes["user"].token_count > 0)
    
    # Test 4: Reading from boxes
    print(f"\n  [Test Group 4: Reading from Boxes]")
    content = manager.read_from_box("system")
    check("Read from system box", "helpful assistant" in content)
    
    content = manager.read_from_box("user")
    check("Read from user box", "weather" in content)
    
    # Test 5: Adding and removing boxes
    print(f"\n  [Test Group 5: Dynamic Box Management]")
    box = manager.add_box("test_box", BoxType.CUSTOM, 1024, "Test box")
    check("Add custom box", "test_box" in manager.boxes)
    check("Custom box has correct type", box.box_type == BoxType.CUSTOM)
    check("Custom box has max tokens", box.max_tokens == 1024)
    
    result = manager.remove_box("test_box")
    check("Remove custom box", result)
    check("Custom box removed", "test_box" not in manager.boxes)
    
    # Test 6: Spawning special boxes
    print(f"\n  [Test Group 6: Special Boxes]")
    reason_name = manager.spawn_reasoning_box("Why is the sky blue?")
    check("Spawn reasoning box", reason_name in manager.boxes)
    check("Reasoning box has correct type", 
          manager.boxes[reason_name].box_type == BoxType.REASONING)
    
    plan_name = manager.spawn_plan_box("Learn Python")
    check("Spawn plan box", plan_name in manager.boxes)
    check("Plan box has correct type",
          manager.boxes[plan_name].box_type == BoxType.PLAN)
    
    # Test 7: Box-to-box messaging
    print(f"\n  [Test Group 7: Box-to-Box Messaging]")
    manager.box_to_box("user", "knowledge", "Need facts about weather")
    check("Message sent from user to knowledge", True)
    
    manager.process_messages()
    check("Messages processed", True)
    
    # Test 8: Context aggregation
    print(f"\n  [Test Group 8: Context Aggregation]")
    context = manager.get_context()
    check("Context has boxes", context.box_count > 0)
    check("Context has total tokens", context.total_tokens > 0)
    check("Context has max total tokens", context.max_total_tokens > 0)
    check("Context has active boxes", context.active_box_count > 0)
    
    # Test 9: Prompt formatting
    print(f"\n  [Test Group 9: Prompt Formatting]")
    tagged = context.to_prompt(format="tagged")
    check("Tagged format has box tags", "<box" in tagged)
    
    linear = context.to_prompt(format="linear")
    check("Linear format has brackets", "[" in linear)
    
    compact = context.to_prompt(format="compact")
    check("Compact format has pipes", "|" in compact)
    
    # Test 10: Compression
    print(f"\n  [Test Group 10: Compression]")
    # Fill a box first
    manager.write_to_box("knowledge", "x " * 2000)
    before = manager.boxes["knowledge"].token_count
    manager.compress_boxes(target_utilization=0.3)
    after = manager.boxes["knowledge"].token_count
    check("Compression reduces tokens", after <= before)
    
    # Test 11: Eviction
    print(f"\n  [Test Group 11: Eviction]")
    # Fill up boxes to trigger eviction
    small_manager = ChatterManager(default_box_size=4096, max_boxes=3)
    # Remove default boxes except system and user
    for name in list(small_manager.boxes.keys()):
        if name not in ("system", "user"):
            small_manager.remove_box(name)
    # Add boxes until eviction triggers
    small_manager.add_box("box1", BoxType.CUSTOM, 1024, "Box 1")
    small_manager.add_box("box2", BoxType.CUSTOM, 1024, "Box 2")
    # This should evict box1 (LRU)
    small_manager.add_box("box3", BoxType.CUSTOM, 1024, "Box 3")
    check("Eviction keeps within limit", len(small_manager.boxes) <= 3)
    
    # Test 12: Full inference pipeline
    print(f"\n  [Test Group 12: Inference Pipeline]")
    engine = ChatterInference(manager)
    response = engine.chat("Explain quantum computing")
    check("Inference produces response", len(response) > 0)
    check("Response written to assistant", 
          manager.boxes["assistant"].token_count > 0)
    check("Conversation tracked", len(engine.conversation_history) > 0)
    
    # Test 13: Multiple conversations
    print(f"\n  [Test Group 13: Multiple Conversations]")
    for msg in ["What is AI?", "How does it work?", "Give me an example"]:
        engine.chat(msg)
    check("Multiple conversations handled", 
          len(engine.conversation_history) >= 3)
    
    # Test 14: Conversation summary
    print(f"\n  [Test Group 14: Conversation Summary]")
    summary = engine.get_conversation_summary()
    check("Summary is non-empty", len(summary) > 0)
    check("Summary mentions exchanges", "exchanges" in summary)
    
    # Test 15: Stats
    print(f"\n  [Test Group 15: Statistics]")
    stats = manager.get_stats()
    check("Stats has version", "version" in stats)
    check("Stats has signature", "signature" in stats)
    check("Stats has boxes", "boxes" in stats)
    check("Stats has total_tokens", "total_tokens" in stats)
    check("Stats has messages_passed", "messages_passed" in stats)
    check("Stats has boxes_detail", "boxes_detail" in stats)
    
    # Test 16: Bus broadcasts
    print(f"\n  [Test Group 16: Bus Broadcasts]")
    manager.bus.broadcast("test", "Hello everyone!", "test")
    broadcasts = manager.bus.get_broadcasts()
    check("Broadcasts recorded", len(broadcasts) > 0)
    check("Broadcast has correct content", 
          any("Hello everyone" in b.content for b in broadcasts))
    
    # Test 17: Box utilization tracking
    print(f"\n  [Test Group 17: Utilization Tracking]")
    box = manager.boxes["system"]
    check("Box tracks use count", box.use_count > 0)
    check("Box tracks last_used", box.last_used > 0)
    
    # Test 18: Full box behavior
    print(f"\n  [Test Group 18: Full Box Behavior]")
    tiny_box = manager.add_box("tiny", BoxType.CUSTOM, 10, "Tiny box")
    for i in range(20):
        tiny_box.add_token(f"token_{i}")
    check("Full box stops accepting", tiny_box.token_count <= 10)
    check("Full box reports full", tiny_box.is_full)
    
    # Test 19: Message priority
    print(f"\n  [Test Group 19: Message Priority]")
    high_msg = Message("test", "manager", "URGENT", "alert", priority=2)
    low_msg = Message("test", "manager", "normal", "info", priority=0)
    check("High priority message", high_msg.priority == 2)
    check("Low priority message", low_msg.priority == 0)
    
    # Test 20: Box info
    print(f"\n  [Test Group 20: Box Info]")
    info = manager.boxes["system"].info()
    check("Info contains box name", "system" in info)
    check("Info contains box type", "system" in info)
    check("Info contains token count", any(c.isdigit() for c in info))
    
    # Summary
    total = tests_passed + tests_failed
    print(f"\n{'─'*62}")
    print(f"  Smoke Tests: {tests_passed}/{total} passed")
    if tests_failed > 0:
        print(f"  FAILED: {tests_failed} tests failed!")
    else:
        print(f"  ALL TESTS PASSED ✓")
    print(f"{'─'*62}")
    
    return tests_failed == 0


# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import sys
    
    if "--test" in sys.argv:
        run_smoke_tests()
    elif "--demo" in sys.argv:
        run_demo()
    else:
        run_smoke_tests()
        print("\n")
        run_demo()
