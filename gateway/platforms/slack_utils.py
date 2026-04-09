"""
Slack-specific utilities for thread handling, caching, and message processing.

This module provides:
- Thread participation cache for implicit mention detection
- Thread history loading for context
- Smart mention gating logic
- SSRF-safe file downloading
- Table formatting support
- Reconnection and resilience utilities
- Connection status tracking
"""

import asyncio
import logging
import time
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SSRF Protection for Slack File Downloads
#
# Slack file URLs should only point to known Slack domains.
# This prevents credential leakage if a malicious URL is crafted.
# ---------------------------------------------------------------------------

SLACK_ALLOWED_HOSTNAMES = (
    "slack.com",
    "*.slack.com", 
    "slack-edge.com",
    "*.slack-edge.com",
    "slack-files.com",
    "*.slack-files.com",
)

import urllib.parse


def is_slack_hostname(hostname: str) -> bool:
    """Check if hostname matches allowed Slack domains."""
    if not hostname:
        return False
    
    hostname = hostname.lower().rstrip(".")
    
    for pattern in SLACK_ALLOWED_HOSTNAMES:
        if pattern.startswith("*."):
            # Wildcard match
            suffix = pattern[2:]  # Remove "*."
            if hostname == suffix or hostname.endswith(f".{suffix}"):
                return True
        else:
            if hostname == pattern:
                return True
    
    return False


def validate_slack_file_url(url: str) -> str:
    """
    Validate that a URL points to a known Slack domain.
    
    Args:
        url: The URL to validate
        
    Returns:
        The validated URL
        
    Raises:
        ValueError: If URL is invalid or points to non-Slack domain
    """
    if not url:
        raise ValueError("Empty URL")
    
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL: {url}") from e
    
    if parsed.scheme not in ("https",):
        raise ValueError(f"Refusing non-HTTPS Slack file URL: {parsed.scheme}")
    
    if not is_slack_hostname(parsed.hostname or ""):
        raise ValueError(
            f"Refusing to send Slack token to non-Slack host: {parsed.hostname}"
        )
    
    return url


def looks_like_html_content(data: bytes) -> bool:
    """
    Check if downloaded content looks like HTML (auth page, error page).
    
    Slack sometimes returns HTML login pages instead of binary files
    when auth fails or the file is unavailable.
    
    Args:
        data: Raw bytes of downloaded content
        
    Returns:
        True if content appears to be HTML
    """
    if len(data) < 10:
        return False
    
    # Check first 512 bytes for HTML markers
    head = data[:512].decode("utf-8", errors="ignore").strip().lower()
    
    return head.startswith("<!doctype html") or head.startswith("<html")


# ---------------------------------------------------------------------------
# Voice Message MIME Type Handling
#
# Slack voice messages (slack_audio subtype) are served with video/* MIME
# types but should be treated as audio for transcription.
# ---------------------------------------------------------------------------

def normalize_slack_voice_mimetype(mimetype: Optional[str], subtype: Optional[str]) -> Optional[str]:
    """
    Normalize MIME type for Slack voice messages.
    
    Slack voice clips have subtype="slack_audio" but are served with
    video/* MIME types. Convert to audio/* for proper handling.
    
    Args:
        mimetype: Original MIME type from file metadata
        subtype: Slack file subtype (e.g., "slack_audio")
        
    Returns:
        Normalized MIME type
    """
    if not mimetype:
        return mimetype
    
    if subtype == "slack_audio" and mimetype.startswith("video/"):
        return mimetype.replace("video/", "audio/", 1)
    
    return mimetype


# ---------------------------------------------------------------------------
# Thread Participation Cache
#
# In-memory cache tracking which threads the bot has participated in.
# Used to allow implicit mentions (no @mention required) after first reply.
# Similar to Hermes' sent-thread-cache pattern.
# ---------------------------------------------------------------------------

class ThreadParticipationCache:
    """
    LRU cache tracking bot participation in Slack threads.
    
    After the bot replies in a thread, subsequent messages in that thread
    don't require an explicit @mention - the bot will respond implicitly.
    
    TTL: 24 hours
    Max entries: 5000 (prevents unbounded memory growth)
    """
    
    def __init__(self, ttl_seconds: int = 24 * 60 * 60, max_entries: int = 5000):
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = asyncio.Lock()
    
    def _make_key(self, account_id: str, channel_id: str, thread_ts: str) -> str:
        return f"{account_id}:{channel_id}:{thread_ts}"
    
    async def record(self, account_id: str, channel_id: str, thread_ts: str) -> None:
        """Record that the bot has participated in a thread."""
        if not account_id or not channel_id or not thread_ts:
            return
        
        key = self._make_key(account_id, channel_id, thread_ts)
        
        async with self._lock:
            # Remove if exists (will be re-added at end for LRU)
            if key in self._cache:
                del self._cache[key]
            
            # Evict oldest if at capacity
            while len(self._cache) >= self._max_entries:
                self._cache.popitem(last=False)
            
            self._cache[key] = time.time()
    
    async def has_participated(self, account_id: str, channel_id: str, thread_ts: str) -> bool:
        """Check if the bot has participated in a thread (within TTL)."""
        if not account_id or not channel_id or not thread_ts:
            return False
        
        key = self._make_key(account_id, channel_id, thread_ts)
        
        async with self._lock:
            if key not in self._cache:
                return False
            
            # Check TTL
            recorded_at = self._cache[key]
            if time.time() - recorded_at > self._ttl_seconds:
                del self._cache[key]
                return False
            
            # Move to end (LRU)
            del self._cache[key]
            self._cache[key] = recorded_at
            return True
    
    async def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        removed = 0
        cutoff = time.time() - self._ttl_seconds
        
        async with self._lock:
            expired_keys = [
                k for k, v in self._cache.items()
                if v < cutoff
            ]
            for key in expired_keys:
                del self._cache[key]
                removed += 1
        
        return removed
    
    async def clear(self) -> None:
        """Clear all entries."""
        async with self._lock:
            self._cache.clear()


# Global singleton instance
_thread_participation_cache: Optional[ThreadParticipationCache] = None


def get_thread_participation_cache() -> ThreadParticipationCache:
    """Get the global thread participation cache instance."""
    global _thread_participation_cache
    if _thread_participation_cache is None:
        _thread_participation_cache = ThreadParticipationCache()
    return _thread_participation_cache


# ---------------------------------------------------------------------------
# Thread History Loading
#
# Fetches previous messages in a thread to provide context when the bot
# is first invoked in a thread session.
# ---------------------------------------------------------------------------

@dataclass
class ThreadMessage:
    """A message from a Slack thread."""
    text: str
    user_id: Optional[str] = None
    bot_id: Optional[str] = None
    ts: Optional[str] = None
    files: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ThreadContext:
    """Context loaded from a Slack thread."""
    thread_starter: Optional[ThreadMessage] = None
    thread_history: List[ThreadMessage] = field(default_factory=list)
    thread_label: Optional[str] = None
    starter_media_paths: List[str] = field(default_factory=list)


async def fetch_thread_history(
    client,
    channel_id: str,
    thread_ts: str,
    current_message_ts: Optional[str] = None,
    limit: int = 20,
) -> List[ThreadMessage]:
    """
    Fetch recent messages from a Slack thread.
    
    Uses cursor pagination and keeps only the latest N messages.
    
    Args:
        client: Slack WebClient (async)
        channel_id: Slack channel ID
        thread_ts: Thread parent timestamp
        current_message_ts: Exclude this message (the triggering one)
        limit: Maximum messages to return (default 20)
    
    Returns:
        List of ThreadMessage objects (oldest to newest)
    """
    messages: List[ThreadMessage] = []
    cursor: Optional[str] = None
    fetch_limit = 200  # Slack's recommended max per page
    
    try:
        while True:
            kwargs = {
                "channel": channel_id,
                "ts": thread_ts,
                "limit": fetch_limit,
                "inclusive": True,
            }
            if cursor:
                kwargs["cursor"] = cursor
            
            response = await client.conversations_replies(**kwargs)
            
            for msg in response.get("messages", []):
                # Skip messages without content
                text = (msg.get("text") or "").strip()
                files = msg.get("files", [])
                if not text and not files:
                    continue
                
                # Skip the current triggering message
                msg_ts = msg.get("ts")
                if current_message_ts and msg_ts == current_message_ts:
                    continue
                
                messages.append(ThreadMessage(
                    text=text,
                    user_id=msg.get("user"),
                    bot_id=msg.get("bot_id"),
                    ts=msg_ts,
                    files=files if files else [],
                ))
                
                # Keep only last N messages
                if len(messages) > limit:
                    messages.pop(0)
            
            # Check for more pages
            cursor = response.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
            
            # Already have enough messages
            if len(messages) >= limit:
                break
        
        return messages
        
    except Exception as e:
        logger.warning("[Slack] Failed to fetch thread history: %s", e)
        return []


async def fetch_thread_starter(
    client,
    channel_id: str,
    thread_ts: str,
) -> Optional[ThreadMessage]:
    """
    Fetch the parent message of a thread.
    
    Args:
        client: Slack WebClient (async)
        channel_id: Slack channel ID
        thread_ts: Thread parent timestamp
    
    Returns:
        ThreadMessage or None if not found
    """
    try:
        response = await client.conversations_replies(
            channel=channel_id,
            ts=thread_ts,
            limit=1,
            inclusive=True,
        )
        
        messages = response.get("messages", [])
        if not messages:
            return None
        
        msg = messages[0]
        text = (msg.get("text") or "").strip()
        if not text:
            return None
        
        return ThreadMessage(
            text=text,
            user_id=msg.get("user"),
            bot_id=msg.get("bot_id"),
            ts=msg.get("ts"),
            files=msg.get("files", []),
        )
        
    except Exception as e:
        logger.debug("[Slack] Failed to fetch thread starter: %s", e)
        return None


async def load_thread_context(
    client,
    channel_id: str,
    thread_ts: str,
    current_message_ts: Optional[str] = None,
    history_limit: int = 20,
    user_name_resolver: Optional[callable] = None,
) -> ThreadContext:
    """
    Load full thread context including starter and recent history.
    
    Args:
        client: Slack WebClient (async)
        channel_id: Slack channel ID
        thread_ts: Thread parent timestamp
        current_message_ts: Exclude this message from history
        history_limit: Max history messages to load
        user_name_resolver: Optional async function to resolve user IDs to names
    
    Returns:
        ThreadContext with starter, history, and metadata
    """
    context = ThreadContext()
    
    # Fetch thread starter
    starter = await fetch_thread_starter(client, channel_id, thread_ts)
    if starter:
        context.thread_starter = starter
        
        # Create a label for the thread
        snippet = ' '.join(starter.text.split())[:80]
        context.thread_label = f"Slack thread: {snippet}" if snippet else "Slack thread"
    
    # Fetch thread history
    history = await fetch_thread_history(
        client,
        channel_id,
        thread_ts,
        current_message_ts,
        history_limit,
    )
    context.thread_history = history
    
    return context


def format_thread_context_for_prompt(
    context: ThreadContext,
    user_name_resolver: Optional[callable] = None,
) -> str:
    """
    Format thread context as a string for injection into the agent prompt.
    
    Args:
        context: ThreadContext object
        user_name_resolver: Optional async function to resolve user IDs
    
    Returns:
        Formatted string for prompt injection
    """
    parts: List[str] = []
    
    # Add thread starter
    if context.thread_starter:
        starter = context.thread_starter
        user_part = f"<@{starter.user_id}>" if starter.user_id else "Unknown"
        if starter.bot_id:
            user_part = "Assistant"
        
        parts.append(f"[Thread started by {user_part}]")
        parts.append(starter.text)
        parts.append("")
    
    # Add thread history
    if context.thread_history:
        parts.append("[Previous thread messages]")
        for msg in context.thread_history:
            user_part = f"<@{msg.user_id}>" if msg.user_id else "Unknown"
            if msg.bot_id:
                user_part = "Assistant"
            parts.append(f"{user_part}: {msg.text}")
        parts.append("")
    
    return "\n".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Smart Mention Detection
#
# Determines if a message should trigger the bot based on:
# 1. Explicit @mention
# 2. Thread participation (bot has replied in this thread)
# 3. Parent ownership (bot started this thread)
# 4. DM (no mention required)
# ---------------------------------------------------------------------------

@dataclass
class MentionGateResult:
    """Result of mention gating logic."""
    should_respond: bool
    was_mentioned: bool
    implicit_mention: bool
    reason: str = ""


def check_mention_gate(
    text: str,
    bot_user_id: Optional[str],
    is_dm: bool,
    thread_ts: Optional[str],
    parent_user_id: Optional[str],
    has_thread_participation: bool,
    require_mention: bool = True,
) -> MentionGateResult:
    """
    Determine if the bot should respond to a message.
    
    Args:
        text: Message text
        bot_user_id: Bot's Slack user ID
        is_dm: Whether this is a DM
        thread_ts: Thread timestamp (None if not in a thread)
        parent_user_id: User ID of thread parent (None if not applicable)
        has_thread_participation: Whether bot has replied in this thread
        require_mention: Whether @mention is required in channels
    
    Returns:
        MentionGateResult with response decision and metadata
    """
    # DMs always respond
    if is_dm:
        return MentionGateResult(
            should_respond=True,
            was_mentioned=False,
            implicit_mention=False,
            reason="DM - no mention required"
        )
    
    # Check for explicit mention
    explicit_mention = False
    if bot_user_id:
        explicit_mention = f"<@{bot_user_id}>" in text
    
    # If explicitly mentioned, always respond
    if explicit_mention:
        return MentionGateResult(
            should_respond=True,
            was_mentioned=True,
            implicit_mention=False,
            reason="Explicit @mention"
        )
    
    # If mention not required, respond
    if not require_mention:
        return MentionGateResult(
            should_respond=True,
            was_mentioned=False,
            implicit_mention=True,
            reason="Mention not required in this channel"
        )
    
    # Check for implicit mention via thread participation
    if thread_ts:
        # Bot started this thread
        if parent_user_id and bot_user_id and parent_user_id == bot_user_id:
            return MentionGateResult(
                should_respond=True,
                was_mentioned=False,
                implicit_mention=True,
                reason="Bot started this thread"
            )
        
        # Bot has participated in this thread
        if has_thread_participation:
            return MentionGateResult(
                should_respond=True,
                was_mentioned=False,
                implicit_mention=True,
                reason="Bot has participated in this thread"
            )
    
    # Not mentioned and no implicit triggers
    return MentionGateResult(
        should_respond=False,
        was_mentioned=False,
        implicit_mention=False,
        reason="No @mention and no implicit triggers"
    )


# ---------------------------------------------------------------------------
# Markdown Table Utilities
#
# Convert markdown tables to Slack-compatible formats.
# Slack doesn't support native markdown tables, so we use:
# 1. Block Kit table blocks (preferred)
# 2. Fallback: code-formatted ASCII tables
# ---------------------------------------------------------------------------

def extract_markdown_tables(content: str) -> List[Tuple[str, str, int, int]]:
    """
    Extract markdown tables from content.
    
    Returns list of (table_content, remaining_content, start_pos, end_pos)
    """
    import re
    
    # Pattern for markdown tables
    # | col1 | col2 | col3 |
    # |------|------|------|
    # | val1 | val2 | val3 |
    table_pattern = re.compile(
        r'(\|[^\n]+\|\n\|[-:\s|]+\|\n(?:\|[^\n]+\|\n?)+)',
        re.MULTILINE
    )
    
    tables = []
    for match in table_pattern.finditer(content):
        tables.append((
            match.group(1).strip(),
            match.start(),
            match.end()
        ))
    
    return tables


def parse_markdown_table(table_text: str) -> Tuple[List[str], List[List[str]]]:
    """
    Parse a markdown table into headers and rows.
    
    Args:
        table_text: Raw markdown table text
    
    Returns:
        Tuple of (headers, rows)
    """
    lines = [
        line.strip()
        for line in table_text.strip().split('\n')
        if line.strip() and line.strip().startswith('|')
    ]
    
    if len(lines) < 2:
        return [], []
    
    # First line is headers
    headers = [
        cell.strip()
        for cell in lines[0].split('|')
        if cell.strip()
    ]
    
    # Skip separator line (index 1), parse data rows
    rows = []
    for line in lines[2:]:
        row = [
            cell.strip()
            for cell in line.split('|')
            if cell.strip() or cell == ''
        ]
        # Only add non-empty rows
        if any(cell for cell in row):
            rows.append(row)
    
    return headers, rows


def format_table_as_code_block(table_text: str) -> str:
    """
    Format a markdown table as a code block (Slack fallback).
    
    This preserves the visual structure without Block Kit.
    """
    headers, rows = parse_markdown_table(table_text)
    
    if not headers:
        return f"```\n{table_text}\n```"
    
    # Calculate column widths
    num_cols = len(headers)
    widths = [len(str(h)) for h in headers]
    
    for row in rows:
        for i, cell in enumerate(row):
            if i < num_cols:
                widths[i] = max(widths[i], len(str(cell)))
    
    # Build formatted table
    lines = []
    
    # Header row
    header_parts = [
        str(headers[i]).ljust(widths[i])
        for i in range(min(len(headers), num_cols))
    ]
    lines.append("| " + " | ".join(header_parts) + " |")
    
    # Separator
    sep_parts = ["-" * w for w in widths[:num_cols]]
    lines.append("| " + " | ".join(sep_parts) + " |")
    
    # Data rows
    for row in rows:
        row_parts = []
        for i in range(num_cols):
            cell = str(row[i]) if i < len(row) else ""
            row_parts.append(cell.ljust(widths[i]))
        lines.append("| " + " | ".join(row_parts) + " |")
    
    return "```\n" + "\n".join(lines) + "\n```"


def convert_markdown_tables_to_slack(content: str, use_block_kit: bool = False) -> Tuple[str, List[Dict]]:
    """
    Convert markdown tables in content to Slack-compatible format.
    
    Args:
        content: Text with markdown tables
        use_block_kit: If True, return Block Kit structures (not yet implemented)
    
    Returns:
        Tuple of (modified_content, blocks)
    """
    tables = extract_markdown_tables(content)
    
    if not tables:
        return content, []
    
    blocks = []
    result = content
    
    # Process tables in reverse order to preserve positions
    for table_text, start, end in reversed(tables):
        if use_block_kit:
            # TODO: Implement Block Kit table blocks when Slack adds them
            # For now, fall back to code block
            formatted = format_table_as_code_block(table_text)
        else:
            formatted = format_table_as_code_block(table_text)
        
        result = result[:start] + formatted + result[end:]
    
    return result, blocks


# ---------------------------------------------------------------------------
# Per-Channel Configuration
#
# Allows fine-grained control over bot behavior per channel:
# - requireMention: Override global setting per channel
# - allowBots: Allow bot messages in this channel
# - users: Whitelist of allowed user IDs
# ---------------------------------------------------------------------------

@dataclass
class SlackChannelConfig:
    """Configuration for a specific Slack channel."""
    channel_id: str
    channel_name: Optional[str] = None
    require_mention: Optional[bool] = None
    allow_bots: Optional[bool] = None
    users: Optional[List[str]] = None
    thread_history_limit: Optional[int] = None
    reply_broadcast: Optional[bool] = None


def resolve_channel_config(
    channel_id: str,
    channel_name: Optional[str],
    global_config: Dict[str, Any],
) -> SlackChannelConfig:
    """
    Resolve the effective configuration for a Slack channel.
    
    Priority (highest to lowest):
    1. Direct channel ID match
    2. Channel name match (if allowNameMatching is enabled)
    3. Global defaults
    
    Args:
        channel_id: Slack channel ID
        channel_name: Human-readable channel name (optional)
        global_config: Global Slack configuration dict
    
    Returns:
        SlackChannelConfig with resolved settings
    """
    channels_config = global_config.get("channels", {})
    allow_name_matching = global_config.get("allowNameMatching", False)
    
    # Try direct ID match first
    channel_config = channels_config.get(channel_id)
    
    # Fall back to name match if enabled
    if not channel_config and allow_name_matching and channel_name:
        channel_config = channels_config.get(channel_name)
        if channel_config:
            logger.debug("[Slack] Matched channel config by name: %s", channel_name)
    
    # Build config with fallbacks to global settings
    return SlackChannelConfig(
        channel_id=channel_id,
        channel_name=channel_name,
        require_mention=channel_config.get("requireMention") if channel_config else None,
        allow_bots=channel_config.get("allowBots") if channel_config else None,
        users=channel_config.get("users") if channel_config else None,
        thread_history_limit=channel_config.get("threadHistoryLimit") if channel_config else None,
        reply_broadcast=channel_config.get("replyBroadcast") if channel_config else None,
    )


def is_user_allowed_in_channel(
    user_id: str,
    user_name: Optional[str],
    channel_config: SlackChannelConfig,
    global_config: Dict[str, Any],
) -> Tuple[bool, str]:
    """
    Check if a user is allowed to interact with the bot in a channel.
    
    Args:
        user_id: Slack user ID
        user_name: Display name (for name matching)
        channel_config: Resolved channel configuration
        global_config: Global configuration
    
    Returns:
        Tuple of (allowed: bool, reason: str)
    """
    allow_name_matching = global_config.get("allowNameMatching", False)
    
    # If no users whitelist, everyone is allowed
    if not channel_config.users:
        return True, "no_user_whitelist"
    
    # Check direct ID match
    if user_id in channel_config.users:
        return True, "user_id_match"
    
    # Check name match if enabled
    if allow_name_matching and user_name:
        normalized_name = user_name.strip().lower()
        for allowed in channel_config.users:
            if allowed.strip().lower() == normalized_name:
                return True, "user_name_match"
    
    return False, "not_in_whitelist"


# ---------------------------------------------------------------------------
# Reconnection and Resilience
#
# Provides exponential backoff with jitter for reconnection attempts,
# detection of non-recoverable auth errors, and connection status tracking.
# ---------------------------------------------------------------------------

import random
from enum import Enum
from typing import Callable, Awaitable


class SlackConnectionStatus(Enum):
    """Connection status for Slack gateway."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


@dataclass
class SlackReconnectPolicy:
    """Configuration for reconnection behavior."""
    initial_ms: float = 2000.0
    max_ms: float = 30000.0
    factor: float = 1.8
    jitter: float = 0.25
    max_attempts: int = 12
    
    def compute_backoff(self, attempt: int) -> float:
        """
        Compute backoff delay with exponential increase and jitter.
        
        Args:
            attempt: Current attempt number (0-indexed)
        
        Returns:
            Delay in milliseconds
        """
        if attempt >= self.max_attempts:
            return self.max_ms
        
        # Exponential backoff
        delay = self.initial_ms * (self.factor ** attempt)
        
        # Cap at max
        delay = min(delay, self.max_ms)
        
        # Add jitter
        jitter_amount = delay * self.jitter
        delay = delay - jitter_amount + (random.random() * 2 * jitter_amount)
        
        return delay


# Non-recoverable auth error patterns
SLACK_AUTH_ERROR_PATTERNS = [
    r"account_inactive",
    r"invalid_auth",
    r"token_revoked",
    r"token_expired",
    r"not_authed",
    r"org_login_required",
    r"team_access_not_granted",
    r"missing_scope",
    r"cannot_find_service",
    r"invalid_token",
]

SLACK_AUTH_ERROR_RE = re.compile(
    "|".join(SLACK_AUTH_ERROR_PATTERNS),
    re.IGNORECASE
)


def is_non_recoverable_slack_error(error: Exception) -> bool:
    """
    Check if an error is non-recoverable (should not retry).
    
    These indicate permanent credential problems:
    - Revoked bot token
    - Deactivated account
    - Expired token
    - Missing scopes
    
    Args:
        error: Exception to check
    
    Returns:
        True if error is non-recoverable
    """
    error_str = str(error)
    if hasattr(error, 'message'):
        error_str = getattr(error, 'message', error_str)
    
    return bool(SLACK_AUTH_ERROR_RE.search(error_str))


def format_slack_error(error: Exception) -> str:
    """Format an error for logging/display."""
    if isinstance(error, Exception):
        return error.message if hasattr(error, 'message') else str(error)
    return str(error)


@dataclass
class SlackConnectionState:
    """Tracks connection state for health monitoring."""
    status: SlackConnectionStatus = SlackConnectionStatus.DISCONNECTED
    last_event_at: Optional[float] = None
    last_inbound_at: Optional[float] = None
    last_disconnect_at: Optional[float] = None
    last_error: Optional[str] = None
    reconnect_attempts: int = 0
    connected_at: Optional[float] = None
    
    def mark_connected(self) -> None:
        """Mark connection as established."""
        self.status = SlackConnectionStatus.CONNECTED
        self.connected_at = time.time()
        self.last_error = None
        self.reconnect_attempts = 0
    
    def mark_disconnected(self, error: Optional[Exception] = None) -> None:
        """Mark connection as lost."""
        self.status = SlackConnectionStatus.DISCONNECTED
        self.last_disconnect_at = time.time()
        if error:
            self.last_error = format_slack_error(error)
    
    def mark_event_received(self) -> None:
        """Mark that an event was received (liveness tracking)."""
        now = time.time()
        self.last_event_at = now
        self.last_inbound_at = now
    
    def get_seconds_since_last_event(self) -> Optional[float]:
        """Get seconds since last event, or None if no events received."""
        if self.last_event_at is None:
            return None
        return time.time() - self.last_event_at
    
    def is_socket_stale(self, stale_threshold_seconds: float = 60.0) -> bool:
        """
        Check if socket appears connected but is stale (no events).
        
        This detects "half-dead" sockets that pass health checks
        but silently stop delivering events.
        
        Args:
            stale_threshold_seconds: Seconds without events to consider stale
        
        Returns:
            True if socket is stale
        """
        if self.status != SlackConnectionStatus.CONNECTED:
            return False
        
        seconds_since = self.get_seconds_since_last_event()
        if seconds_since is None:
            # No events received yet, check how long we've been "connected"
            if self.connected_at:
                return (time.time() - self.connected_at) > stale_threshold_seconds
            return False
        
        return seconds_since > stale_threshold_seconds


class SlackReconnectionManager:
    """
    Manages reconnection logic for Slack gateway.
    
    Features:
    - Exponential backoff with jitter
    - Non-recoverable error detection
    - Connection state tracking
    - Stale socket detection
    """
    
    def __init__(
        self,
        policy: Optional[SlackReconnectPolicy] = None,
        stale_threshold_seconds: float = 60.0,
        on_status_change: Optional[Callable[[SlackConnectionStatus], Awaitable[None]]] = None,
    ):
        self.policy = policy or SlackReconnectPolicy()
        self.state = SlackConnectionState()
        self.stale_threshold_seconds = stale_threshold_seconds
        self.on_status_change = on_status_change
        self._should_stop = False
    
    def should_retry(self, error: Optional[Exception] = None) -> bool:
        """
        Determine if we should attempt reconnection.
        
        Args:
            error: Optional error that caused disconnect
        
        Returns:
            True if we should retry, False if non-recoverable
        """
        if self._should_stop:
            return False
        
        if error and is_non_recoverable_slack_error(error):
            logger.error("[Slack] Non-recoverable auth error: %s", format_slack_error(error))
            return False
        
        if self.state.reconnect_attempts >= self.policy.max_attempts:
            logger.error("[Slack] Max reconnection attempts (%d) reached", self.policy.max_attempts)
            return False
        
        return True
    
    def get_backoff_delay(self) -> float:
        """Get backoff delay for current attempt in seconds."""
        delay_ms = self.policy.compute_backoff(self.state.reconnect_attempts)
        return delay_ms / 1000.0  # Convert to seconds
    
    async def wait_with_backoff(self) -> None:
        """Wait with exponential backoff before next reconnection attempt."""
        delay = self.get_backoff_delay()
        logger.info(
            "[Slack] Waiting %.1fs before reconnection attempt %d/%d",
            delay,
            self.state.reconnect_attempts + 1,
            self.policy.max_attempts,
        )
        await asyncio.sleep(delay)
    
    def begin_reconnection(self) -> None:
        """Mark beginning of reconnection attempt."""
        self.state.reconnect_attempts += 1
        self.state.status = SlackConnectionStatus.RECONNECTING
    
    def mark_connected(self) -> None:
        """Mark successful connection."""
        self.state.mark_connected()
        logger.info(
            "[Slack] Connected successfully after %d attempts",
            self.state.reconnect_attempts,
        )
    
    def mark_disconnected(self, error: Optional[Exception] = None) -> None:
        """Mark disconnection."""
        self.state.mark_disconnected(error)
        if error:
            logger.warning("[Slack] Disconnected: %s", format_slack_error(error))
        else:
            logger.info("[Slack] Disconnected")
    
    def mark_event_received(self) -> None:
        """Mark that an event was received."""
        self.state.mark_event_received()
    
    def check_stale_socket(self) -> bool:
        """Check if socket is stale and needs reconnection."""
        if self.state.is_socket_stale(self.stale_threshold_seconds):
            logger.warning(
                "[Slack] Socket stale (no events for %.1fs), reconnecting",
                self.state.get_seconds_since_last_event(),
            )
            return True
        return False
    
    def stop(self) -> None:
        """Stop reconnection attempts."""
        self._should_stop = True
    
    def reset(self) -> None:
        """Reset state for fresh start."""
        self.state = SlackConnectionState()
        self._should_stop = False


# ---------------------------------------------------------------------------
# Scope Validation
#
# Utilities for validating Slack OAuth scopes.
# ---------------------------------------------------------------------------

REQUIRED_SLACK_SCOPES = {
    "chat:write",
    "app_mentions:read",
    "channels:history",
    "groups:history",
    "im:history",
    "im:read",
    "im:write",
    "files:read",
    "files:write",
    "reactions:write",
}

RECOMMENDED_SLACK_SCOPES = {
    "users:read",
    "users:read.email",
    "channels:read",
    "groups:read",
    "mpim:history",
    "mpim:read",
    "mpim:write",
}


@dataclass
class SlackScopeValidation:
    """Result of scope validation."""
    valid: bool
    missing_required: List[str]
    missing_recommended: List[str]
    all_scopes: List[str]
    
    def format_warning(self) -> str:
        """Format a warning message for missing scopes."""
        lines = []
        
        if self.missing_required:
            lines.append(f"[Slack] WARNING: Missing required scopes: {', '.join(self.missing_required)}")
            lines.append("  These scopes are required for full functionality.")
        
        if self.missing_recommended:
            lines.append(f"[Slack] NOTE: Missing recommended scopes: {', '.join(self.missing_recommended)}")
            lines.append("  These scopes enhance functionality but are not required.")
        
        return "\n".join(lines)


async def fetch_slack_scopes(client, timeout_ms: int = 5000) -> List[str]:
    """
    Fetch granted OAuth scopes from Slack API.
    
    Tries multiple API methods:
    1. auth.scopes (preferred)
    2. apps.permissions.info (fallback)
    
    Args:
        client: Slack WebClient
        timeout_ms: Timeout in milliseconds
    
    Returns:
        List of granted scope strings
    """
    scopes = []
    
    # Try auth.scopes first (newer API)
    try:
        result = await asyncio.wait_for(
            client.auth_scopes_list(),
            timeout=timeout_ms / 1000,
        )
        if result.get("ok"):
            scopes.extend(result.get("scopes", []))
    except Exception:
        pass
    
    # Fallback to apps.permissions.info
    if not scopes:
        try:
            result = await asyncio.wait_for(
                client.apps_permissions_info(),
                timeout=timeout_ms / 1000,
            )
            if result.get("ok"):
                info = result.get("info", {})
                scopes.extend(info.get("scopes", []))
                scopes.extend(info.get("bot_scopes", []))
        except Exception:
            pass
    
    return list(set(s.strip() for s in scopes if s and s.strip()))


def validate_slack_scopes(granted_scopes: List[str]) -> SlackScopeValidation:
    """
    Validate that required scopes are granted.
    
    Args:
        granted_scopes: List of scopes granted to the app
    
    Returns:
        SlackScopeValidation with missing scopes
    """
    granted_set = set(s.lower() for s in granted_scopes)
    
    missing_required = sorted(
        s for s in REQUIRED_SLACK_SCOPES
        if s.lower() not in granted_set
    )
    
    missing_recommended = sorted(
        s for s in RECOMMENDED_SLACK_SCOPES
        if s.lower() not in granted_set
    )
    
    return SlackScopeValidation(
        valid=len(missing_required) == 0,
        missing_required=missing_required,
        missing_recommended=missing_recommended,
        all_scopes=sorted(granted_scopes),
    )


# ---------------------------------------------------------------------------
# Health Probe
#
# Simple health check for Slack connection.
# ---------------------------------------------------------------------------

@dataclass
class SlackProbeResult:
    """Result of Slack connection probe."""
    ok: bool
    error: Optional[str] = None
    elapsed_ms: Optional[float] = None
    bot_id: Optional[str] = None
    bot_name: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None


async def probe_slack_connection(
    client,
    timeout_ms: int = 2500,
) -> SlackProbeResult:
    """
    Probe Slack connection health.
    
    Args:
        client: Slack WebClient
        timeout_ms: Timeout in milliseconds
    
    Returns:
        SlackProbeResult with connection info
    """
    start = time.time()
    
    try:
        result = await asyncio.wait_for(
            client.auth_test(),
            timeout=timeout_ms / 1000,
        )
        
        if not result.get("ok"):
            return SlackProbeResult(
                ok=False,
                error=result.get("error", "unknown"),
                elapsed_ms=(time.time() - start) * 1000,
            )
        
        return SlackProbeResult(
            ok=True,
            elapsed_ms=(time.time() - start) * 1000,
            bot_id=result.get("user_id"),
            bot_name=result.get("user"),
            team_id=result.get("team_id"),
            team_name=result.get("team"),
        )
        
    except asyncio.TimeoutError:
        return SlackProbeResult(
            ok=False,
            error="timeout",
            elapsed_ms=(time.time() - start) * 1000,
        )
    except Exception as e:
        return SlackProbeResult(
            ok=False,
            error=format_slack_error(e),
            elapsed_ms=(time.time() - start) * 1000,
        )


# ---------------------------------------------------------------------------
# Message Updating
#
# Utilities for updating existing messages (progress, approvals).
# ---------------------------------------------------------------------------

@dataclass
class SlackMessageRef:
    """Reference to an existing Slack message."""
    channel_id: str
    message_ts: str


async def update_slack_message(
    client,
    message_ref: SlackMessageRef,
    text: str,
    blocks: Optional[List[Dict]] = None,
) -> bool:
    """
    Update an existing Slack message.
    
    Args:
        client: Slack WebClient
        message_ref: Reference to message to update
        text: New message text
        blocks: Optional new blocks
    
    Returns:
        True if update succeeded
    """
    try:
        params = {
            "channel": message_ref.channel_id,
            "ts": message_ref.message_ts,
            "text": text,
        }
        if blocks:
            params["blocks"] = blocks
        
        result = await client.chat_update(**params)
        return result.get("ok", False)
        
    except Exception as e:
        logger.error("[Slack] Failed to update message: %s", format_slack_error(e))
        return False


def build_approval_blocks(
    title: str,
    description: str,
    approval_id: str,
    allow_always: bool = True,
) -> List[Dict]:
    """
    Build Block Kit blocks for approval message.
    
    Args:
        title: Approval title
        description: Description of what needs approval
        approval_id: Unique ID for tracking
        allow_always: Whether to show "Always Allow" button
    
    Returns:
        List of Block Kit blocks
    """
    buttons = [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "Approve"},
            "style": "primary",
            "action_id": f"approval:approve:{approval_id}",
        },
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "Deny"},
            "style": "danger",
            "action_id": f"approval:deny:{approval_id}",
        },
    ]
    
    if allow_always:
        buttons.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "Always Allow"},
            "action_id": f"approval:always:{approval_id}",
        })
    
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{title}*\n{description}",
            },
        },
        {
            "type": "actions",
            "elements": buttons,
        },
    ]


def build_resolved_approval_blocks(
    title: str,
    description: str,
    resolved_by: str,
    decision: str,
) -> List[Dict]:
    """
    Build Block Kit blocks for resolved approval message.
    
    Args:
        title: Approval title
        description: Original description
        resolved_by: User who resolved
        decision: "approved", "denied", or "always"
    
    Returns:
        List of Block Kit blocks
    """
    decision_emoji = {
        "approved": "white_check_mark",
        "denied": "x",
        "always": "white_check_mark",
    }.get(decision, "white_check_mark")
    
    decision_label = {
        "approved": "Approved",
        "denied": "Denied",
        "always": "Always Allowed",
    }.get(decision, decision.title())
    
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{title}*\n{description}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f":{decision_emoji}: {decision_label} by <@{resolved_by}>",
                },
            ],
        },
    ]
