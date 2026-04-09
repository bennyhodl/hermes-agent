"""
Slack platform adapter.

Uses slack-bolt (Python) with Socket Mode for:
- Receiving messages from channels and DMs
- Sending responses back
- Handling slash commands
- Thread support
- Thread history loading for context
- Smart mention detection (implicit mentions after participation)
- Table formatting support
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Dict, Optional, Any, List, Tuple

try:
    from slack_bolt.async_app import AsyncApp
    from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
    from slack_sdk.web.async_client import AsyncWebClient
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
    AsyncApp = Any
    AsyncSocketModeHandler = Any
    AsyncWebClient = Any

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    SUPPORTED_DOCUMENT_TYPES,
    cache_document_from_bytes,
)
from gateway.platforms.slack_utils import (
    get_thread_participation_cache,
    check_mention_gate,
    load_thread_context,
    format_thread_context_for_prompt,
    convert_markdown_tables_to_slack,
    validate_slack_file_url,
    looks_like_html_content,
    normalize_slack_voice_mimetype,
    resolve_channel_config,
    is_user_allowed_in_channel,
    SlackChannelConfig,
    # Connection state tracking
    SlackConnectionState,
    is_non_recoverable_slack_error,
    format_slack_error,
    # Scope validation
    fetch_slack_scopes,
    validate_slack_scopes,
    SlackScopeValidation,
    REQUIRED_SLACK_SCOPES,
    RECOMMENDED_SLACK_SCOPES,
    # Health probe
    probe_slack_connection,
    SlackProbeResult,
    # Message updating
    update_slack_message,
    SlackMessageRef,
)


logger = logging.getLogger(__name__)


def check_slack_requirements() -> bool:
    """Check if Slack dependencies are available."""
    return SLACK_AVAILABLE


class SlackAdapter(BasePlatformAdapter):
    """
    Slack bot adapter using Socket Mode.

    Requires two tokens:
      - SLACK_BOT_TOKEN (xoxb-...) for API calls
      - SLACK_APP_TOKEN (xapp-...) for Socket Mode connection

    Features:
      - DMs and channel messages (mention-gated in channels)
      - Thread support
      - File/image/audio attachments
      - Slash commands (/hermes)
      - Typing indicators (not natively supported by Slack bots)
    """

    MAX_MESSAGE_LENGTH = 39000  # Slack API allows 40,000 chars; leave margin

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.SLACK)
        self._app: Optional[AsyncApp] = None
        self._handler: Optional[AsyncSocketModeHandler] = None
        self._bot_user_id: Optional[str] = None
        self._user_name_cache: Dict[str, str] = {}  # user_id → display name
        self._socket_mode_task: Optional[asyncio.Task] = None
        # Multi-workspace support
        self._team_clients: Dict[str, AsyncWebClient] = {}   # team_id → WebClient
        self._team_bot_user_ids: Dict[str, str] = {}          # team_id → bot_user_id
        self._channel_team: Dict[str, str] = {}                # channel_id → team_id
        # Dedup cache: event_ts → timestamp.  Prevents duplicate bot
        # responses when Socket Mode reconnects redeliver events.
        self._seen_messages: Dict[str, float] = {}
        self._SEEN_TTL = 300   # 5 minutes
        self._SEEN_MAX = 2000  # prune threshold
        # Track pending approval message_ts → resolved flag to prevent
        # double-clicks on approval buttons.
        self._approval_resolved: Dict[str, bool] = {}
        # Connection state tracking (for health checks and stale socket detection)
        # Note: Reconnection is handled by gateway/run.py at the platform level
        self._connection_state: SlackConnectionState = SlackConnectionState()
        # Message tracking for updates
        self._pending_messages: Dict[str, SlackMessageRef] = {}  # id → ref
        # Assistant thread metadata keyed by (channel_id, thread_ts). Slack's
        # AI Assistant lifecycle events can arrive before/alongside message
        # events, and they carry the user/thread identity needed for stable
        # session + memory scoping.
        self._assistant_threads: Dict[Tuple[str, str], Dict[str, str]] = {}
        self._ASSISTANT_THREADS_MAX = 5000

    async def connect(self) -> bool:
        """Connect to Slack via Socket Mode."""
        if not SLACK_AVAILABLE:
            logger.error(
                "[Slack] slack-bolt not installed. Run: pip install slack-bolt",
            )
            return False

        raw_token = self.config.token
        app_token = os.getenv("SLACK_APP_TOKEN")

        if not raw_token:
            logger.error("[Slack] SLACK_BOT_TOKEN not set")
            return False
        if not app_token:
            logger.error("[Slack] SLACK_APP_TOKEN not set")
            return False

        # Support comma-separated bot tokens for multi-workspace
        bot_tokens = [t.strip() for t in raw_token.split(",") if t.strip()]

        # Also load tokens from OAuth token file
        from hermes_constants import get_hermes_home
        tokens_file = get_hermes_home() / "slack_tokens.json"
        if tokens_file.exists():
            try:
                saved = json.loads(tokens_file.read_text(encoding="utf-8"))
                for team_id, entry in saved.items():
                    tok = entry.get("token", "") if isinstance(entry, dict) else ""
                    if tok and tok not in bot_tokens:
                        bot_tokens.append(tok)
                        team_label = entry.get("team_name", team_id) if isinstance(entry, dict) else team_id
                        logger.info("[Slack] Loaded saved token for workspace %s", team_label)
            except Exception as e:
                logger.warning("[Slack] Failed to read %s: %s", tokens_file, e)

        try:
            # Acquire scoped lock to prevent duplicate app token usage
            from gateway.status import acquire_scoped_lock
            self._token_lock_identity = app_token
            acquired, existing = acquire_scoped_lock('slack-app-token', app_token, metadata={'platform': 'slack'})
            if not acquired:
                owner_pid = existing.get('pid') if isinstance(existing, dict) else None
                message = f'Slack app token already in use' + (f' (PID {owner_pid})' if owner_pid else '') + '. Stop the other gateway first.'
                logger.error('[%s] %s', self.name, message)
                self._set_fatal_error('slack_token_lock', message, retryable=False)
                return False

            # First token is the primary — used for AsyncApp / Socket Mode
            primary_token = bot_tokens[0]
            self._app = AsyncApp(token=primary_token)

            # Register each bot token and map team_id → client
            for token in bot_tokens:
                client = AsyncWebClient(token=token)
                auth_response = await client.auth_test()
                team_id = auth_response.get("team_id", "")
                bot_user_id = auth_response.get("user_id", "")
                bot_name = auth_response.get("user", "unknown")
                team_name = auth_response.get("team", "unknown")

                self._team_clients[team_id] = client
                self._team_bot_user_ids[team_id] = bot_user_id

                # First token sets the primary bot_user_id (backward compat)
                if self._bot_user_id is None:
                    self._bot_user_id = bot_user_id

                logger.info(
                    "[Slack] Authenticated as @%s in workspace %s (team: %s)",
                    bot_name, team_name, team_id,
                )

            # Register message event handler
            @self._app.event("message")
            async def handle_message_event(event, say):
                await self._handle_slack_message(event)

            # Acknowledge app_mention events to prevent Bolt 404 errors.
            # The "message" handler above already processes @mentions in
            # channels, so this is intentionally a no-op to avoid duplicates.
            @self._app.event("app_mention")
            async def handle_app_mention(event, say):
                pass

            @self._app.event("assistant_thread_started")
            async def handle_assistant_thread_started(event, say):
                await self._handle_assistant_thread_lifecycle_event(event)

            @self._app.event("assistant_thread_context_changed")
            async def handle_assistant_thread_context_changed(event, say):
                await self._handle_assistant_thread_lifecycle_event(event)

            # Register slash command handler
            @self._app.command("/hermes")
            async def handle_hermes_command(ack, command):
                await ack()
                await self._handle_slash_command(command)

            # Register Block Kit action handlers for approval buttons
            for _action_id in (
                "hermes_approve_once",
                "hermes_approve_session",
                "hermes_approve_always",
                "hermes_deny",
            ):
                self._app.action(_action_id)(self._handle_approval_action)

            # Register interactive component handler (block_actions)
            # This handles button clicks, select menu choices, etc.
            @self._app.action(re.compile(r"hermes:.*"))
            async def handle_block_action(ack, body, respond):
                await ack()
                await self._handle_block_action(body, respond)

            # Start Socket Mode handler in background
            self._handler = AsyncSocketModeHandler(self._app, app_token)
            self._socket_mode_task = asyncio.create_task(self._handler.start_async())

            # Mark connection state as connected
            self._connection_state.mark_connected()
            
            # Validate OAuth scopes (non-blocking warning)
            try:
                validation = await self.validate_scopes()
                if not validation.valid:
                    logger.warning("[Slack] %s", validation.format_warning())
            except Exception as e:
                logger.debug("[Slack] Scope validation skipped: %s", e)

            self._running = True
            logger.info(
                "[Slack] Socket Mode connected (%d workspace(s))",
                len(self._team_clients),
            )
            return True

        except Exception as e:  # pragma: no cover - defensive logging
            logger.error("[Slack] Connection failed: %s", e, exc_info=True)
            return False

    async def disconnect(self) -> None:
        """Disconnect from Slack."""
        # Mark connection state as disconnected
        self._connection_state.mark_disconnected()
        
        if self._handler:
            try:
                await self._handler.close_async()
            except Exception as e:  # pragma: no cover - defensive logging
                logger.warning("[Slack] Error while closing Socket Mode handler: %s", e, exc_info=True)
        self._running = False

        # Release the token lock (use stored identity, not re-read env)
        try:
            from gateway.status import release_scoped_lock
            if getattr(self, '_token_lock_identity', None):
                release_scoped_lock('slack-app-token', self._token_lock_identity)
                self._token_lock_identity = None
        except Exception:
            pass

        logger.info("[Slack] Disconnected")

    def _get_client(self, chat_id: str) -> AsyncWebClient:
        """Return the workspace-specific WebClient for a channel."""
        team_id = self._channel_team.get(chat_id)
        if team_id and team_id in self._team_clients:
            return self._team_clients[team_id]
        return self._app.client  # fallback to primary

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        blocks: Optional[List[Dict[str, Any]]] = None,
    ) -> SendResult:
        """Send a message to a Slack channel or DM.
        
        Args:
            chat_id: Slack channel ID
            content: Message text (fallback for notifications)
            reply_to: Message ID to reply to
            metadata: Optional metadata dict
            blocks: Optional Block Kit blocks for rich formatting
        """
        if not self._app:
            return SendResult(success=False, error="Not connected")

        try:
            # Convert standard markdown → Slack mrkdwn
            formatted = self.format_message(content)

            # If blocks provided, use them for rich content
            if blocks:
                # Validate blocks structure
                validated_blocks = self._validate_blocks(blocks)
                text = formatted or " "  # Fallback text required
                
                thread_ts = self._resolve_thread_ts(reply_to, metadata)
                
                result = await self._get_client(chat_id).chat_postMessage(
                    channel=chat_id,
                    text=text,
                    blocks=validated_blocks,
                    thread_ts=thread_ts,
                )
                return SendResult(
                    success=True,
                    message_id=result.get("ts"),
                    raw_response=result,
                )

            # Split long messages, preserving code block boundaries
            chunks = self.truncate_message(formatted, self.MAX_MESSAGE_LENGTH)

            thread_ts = self._resolve_thread_ts(reply_to, metadata)
            last_result = None

            # reply_broadcast: also post thread replies to the main channel.
            # Controlled via platform config: gateway.slack.reply_broadcast
            broadcast = self.config.extra.get("reply_broadcast", False)

            for i, chunk in enumerate(chunks):
                kwargs: Dict[str, Any] = {
                    "channel": chat_id,
                    "text": chunk,
                    "blocks": self._content_to_blocks(chunk),
                }
                if thread_ts:
                    kwargs["thread_ts"] = thread_ts
                    # Only broadcast the first chunk of the first reply
                    if broadcast and i == 0:
                        kwargs["reply_broadcast"] = True

                last_result = await self._get_client(chat_id).chat_postMessage(**kwargs)

            # Record thread participation so we auto-respond to future
            # thread replies without requiring @mention.
            sent_ts = last_result.get("ts") if last_result else None
            if sent_ts and thread_ts:
                cache = get_thread_participation_cache()
                await cache.record("default", chat_id, thread_ts)

            return SendResult(
                success=True,
                message_id=sent_ts,
                raw_response=last_result,
            )

        except Exception as e:  # pragma: no cover - defensive logging
            logger.error("[Slack] Send error: %s", e, exc_info=True)
            return SendResult(success=False, error=str(e))

    def _validate_blocks(self, blocks: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Validate and sanitize Block Kit blocks.
        
        - Limits to 50 blocks (Slack API limit)
        - Ensures each block has required type field
        - Truncates long text fields
        """
        if not blocks:
            return []
        
        MAX_BLOCKS = 50
        MAX_TEXT_LENGTH = 3000
        MAX_PLAIN_TEXT = 75
        
        validated = []
        for block in blocks[:MAX_BLOCKS]:
            if not isinstance(block, dict):
                continue
            if "type" not in block:
                continue
            
            # Deep copy to avoid mutating input
            block_copy = json.loads(json.dumps(block))
            
            # Truncate text fields
            if "text" in block_copy:
                text_obj = block_copy["text"]
                if isinstance(text_obj, dict):
                    max_len = MAX_PLAIN_TEXT if text_obj.get("type") == "plain_text" else MAX_TEXT_LENGTH
                    if "text" in text_obj and len(str(text_obj["text"])) > max_len:
                        text_obj["text"] = str(text_obj["text"])[:max_len - 3] + "..."
            
            validated.append(block_copy)
        
        return validated

    def _content_to_blocks(self, mrkdwn_content: str) -> List[Dict[str, Any]]:
        """Convert mrkdwn content into Block Kit blocks.

        Mirrors how ``send_exec_approval`` builds blocks — section blocks
        with ``mrkdwn`` text — so every message sent to Slack uses the
        ``blocks`` parameter for native rendering.

        Splits on ``---`` dividers and leading ``*Header*`` lines (which
        ``format_message`` produces from ``# Header`` markdown).
        """
        if not mrkdwn_content or not mrkdwn_content.strip():
            return [{"type": "section", "text": {"type": "mrkdwn", "text": " "}}]

        blocks: List[Dict[str, Any]] = []
        # Split on horizontal-rule dividers (--- on its own line)
        segments = re.split(r'^-{3,}\s*$', mrkdwn_content, flags=re.MULTILINE)

        for seg_idx, segment in enumerate(segments):
            segment = segment.strip()
            if not segment:
                if seg_idx > 0:
                    blocks.append({"type": "divider"})
                continue

            # Add divider between segments (except before the first)
            if seg_idx > 0:
                blocks.append({"type": "divider"})

            # Section text limit is 3000 chars
            if len(segment) <= 3000:
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": segment},
                })
            else:
                # Split oversized sections at line boundaries
                chunk = ""
                for line in segment.split("\n"):
                    if len(chunk) + len(line) + 1 > 3000:
                        if chunk:
                            blocks.append({
                                "type": "section",
                                "text": {"type": "mrkdwn", "text": chunk},
                            })
                        chunk = line
                    else:
                        chunk = f"{chunk}\n{line}" if chunk else line
                if chunk:
                    blocks.append({
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": chunk},
                    })

        if not blocks:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": " "}})

        # Slack limit: 50 blocks per message
        return blocks[:50]

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
    ) -> SendResult:
        """Edit a previously sent Slack message."""
        if not self._app:
            return SendResult(success=False, error="Not connected")
        try:
            # Convert standard markdown → Slack mrkdwn
            formatted = self.format_message(content)

            await self._get_client(chat_id).chat_update(
                channel=chat_id,
                ts=message_id,
                text=formatted,
            )
            return SendResult(success=True, message_id=message_id)
        except Exception as e:  # pragma: no cover - defensive logging
            logger.error(
                "[Slack] Failed to edit message %s in channel %s: %s",
                message_id,
                chat_id,
                e,
                exc_info=True,
            )
            return SendResult(success=False, error=str(e))

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Show a typing/status indicator using assistant.threads.setStatus.

        Displays "is thinking..." next to the bot name in a thread.
        Requires the assistant:write or chat:write scope.
        Auto-clears when the bot sends a reply to the thread.
        """
        if not self._app:
            return

        thread_ts = None
        if metadata:
            thread_ts = metadata.get("thread_id") or metadata.get("thread_ts")

        if not thread_ts:
            return  # Can only set status in a thread context

        try:
            await self._get_client(chat_id).assistant_threads_setStatus(
                channel_id=chat_id,
                thread_ts=thread_ts,
                status="is thinking...",
            )
        except Exception as e:
            # Silently ignore — may lack assistant:write scope or not be
            # in an assistant-enabled context. Falls back to reactions.
            logger.debug("[Slack] assistant.threads.setStatus failed: %s", e)

    def _resolve_thread_ts(
        self,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Resolve the correct thread_ts for a Slack API call.

        Prefers metadata thread_id (the thread parent's ts, set by the
        gateway) over reply_to (which may be a child message's ts).

        When ``reply_in_thread`` is ``false`` in the platform extra config,
        top-level channel messages receive direct channel replies instead of
        thread replies.  Messages that originate inside an existing thread are
        always replied to in-thread to preserve conversation context.
        """
        # When reply_in_thread is disabled (default: True for backward compat),
        # only thread messages that are already part of an existing thread.
        if not self.config.extra.get("reply_in_thread", True):
            existing_thread = (metadata or {}).get("thread_id") or (metadata or {}).get("thread_ts")
            return existing_thread or None

        if metadata:
            if metadata.get("thread_id"):
                return metadata["thread_id"]
            if metadata.get("thread_ts"):
                return metadata["thread_ts"]
        return reply_to

    async def _upload_file(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Upload a local file to Slack."""
        if not self._app:
            return SendResult(success=False, error="Not connected")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        result = await self._get_client(chat_id).files_upload_v2(
            channel=chat_id,
            file=file_path,
            filename=os.path.basename(file_path),
            initial_comment=caption or "",
            thread_ts=self._resolve_thread_ts(reply_to, metadata),
        )
        return SendResult(success=True, raw_response=result)

    # ----- Markdown → mrkdwn conversion -----

    def format_message(self, content: str) -> str:
        """Convert standard markdown to Slack mrkdwn format.

        Protected regions (code blocks, inline code) are extracted first so
        their contents are never modified.  Standard markdown constructs
        (headers, bold, italic, links) are translated to mrkdwn syntax.
        Tables are converted to code blocks since Slack doesn't support
        native markdown tables.
        """
        if not content:
            return content

        # Convert markdown tables to Slack-compatible format
        content, _ = convert_markdown_tables_to_slack(content, use_block_kit=False)

        placeholders: dict = {}
        counter = [0]

        def _ph(value: str) -> str:
            """Stash value behind a placeholder that survives later passes."""
            key = f"\x00SL{counter[0]}\x00"
            counter[0] += 1
            placeholders[key] = value
            return key

        text = content

        # 1) Protect fenced code blocks (``` ... ```)
        text = re.sub(
            r'(```(?:[^\n]*\n)?[\s\S]*?```)',
            lambda m: _ph(m.group(0)),
            text,
        )

        # 2) Protect inline code (`...`)
        text = re.sub(r'(`[^`]+`)', lambda m: _ph(m.group(0)), text)

        # 3) Convert markdown links [text](url) → <url|text>
        text = re.sub(
            r'\[([^\]]+)\]\(([^)]+)\)',
            lambda m: _ph(f'<{m.group(2)}|{m.group(1)}>'),
            text,
        )

        # 4) Convert headers (## Title) → *Title* (bold)
        def _convert_header(m):
            inner = m.group(1).strip()
            # Strip redundant bold markers inside a header
            inner = re.sub(r'\*\*(.+?)\*\*', r'\1', inner)
            return _ph(f'*{inner}*')

        text = re.sub(
            r'^#{1,6}\s+(.+)$', _convert_header, text, flags=re.MULTILINE
        )

        # 5) Convert bold: **text** → *text* (Slack bold)
        text = re.sub(
            r'\*\*(.+?)\*\*',
            lambda m: _ph(f'*{m.group(1)}*'),
            text,
        )

        # 6) Convert italic: _text_ stays as _text_ (already Slack italic)
        #    Single *text* → _text_ (Slack italic)
        text = re.sub(
            r'(?<!\*)\*([^*\n]+)\*(?!\*)',
            lambda m: _ph(f'_{m.group(1)}_'),
            text,
        )

        # 7) Convert strikethrough: ~~text~~ → ~text~
        text = re.sub(
            r'~~(.+?)~~',
            lambda m: _ph(f'~{m.group(1)}~'),
            text,
        )

        # 8) Convert blockquotes: > text → > text (same syntax, just ensure
        #    no extra escaping happens to the > character)
        # Slack uses the same > prefix, so this is a no-op for content.

        # 9) Restore placeholders in reverse order
        for key in reversed(list(placeholders.keys())):
            text = text.replace(key, placeholders[key])

        return text

    # ----- Reactions -----

    async def _add_reaction(
        self, channel: str, timestamp: str, emoji: str
    ) -> bool:
        """Add an emoji reaction to a message. Returns True on success."""
        if not self._app:
            return False
        try:
            await self._get_client(channel).reactions_add(
                channel=channel, timestamp=timestamp, name=emoji
            )
            return True
        except Exception as e:
            # Don't log as error — may fail if already reacted or missing scope
            logger.debug("[Slack] reactions.add failed (%s): %s", emoji, e)
            return False

    async def _remove_reaction(
        self, channel: str, timestamp: str, emoji: str
    ) -> bool:
        """Remove an emoji reaction from a message. Returns True on success."""
        if not self._app:
            return False
        try:
            await self._get_client(channel).reactions_remove(
                channel=channel, timestamp=timestamp, name=emoji
            )
            return True
        except Exception as e:
            logger.debug("[Slack] reactions.remove failed (%s): %s", emoji, e)
            return False

    # ----- User identity resolution -----

    async def _resolve_user_name(self, user_id: str, chat_id: str = "") -> str:
        """Resolve a Slack user ID to a display name, with caching."""
        if not user_id:
            return ""
        if user_id in self._user_name_cache:
            return self._user_name_cache[user_id]

        if not self._app:
            return user_id

        try:
            client = self._get_client(chat_id) if chat_id else self._app.client
            result = await client.users_info(user=user_id)
            user = result.get("user", {})
            # Prefer display_name → real_name → user_id
            profile = user.get("profile", {})
            name = (
                profile.get("display_name")
                or profile.get("real_name")
                or user.get("real_name")
                or user.get("name")
                or user_id
            )
            self._user_name_cache[user_id] = name
            return name
        except Exception as e:
            logger.debug("[Slack] users.info failed for %s: %s", user_id, e)
            self._user_name_cache[user_id] = user_id
            return user_id

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a local image file to Slack by uploading it."""
        try:
            return await self._upload_file(chat_id, image_path, caption, reply_to, metadata)
        except FileNotFoundError:
            return SendResult(success=False, error=f"Image file not found: {image_path}")
        except Exception as e:  # pragma: no cover - defensive logging
            logger.error(
                "[%s] Failed to send local Slack image %s: %s",
                self.name,
                image_path,
                e,
                exc_info=True,
            )
            text = f"🖼️ Image: {image_path}"
            if caption:
                text = f"{caption}\n{text}"
            return await self.send(chat_id, text, reply_to=reply_to, metadata=metadata)

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send an image to Slack by uploading the URL as a file."""
        if not self._app:
            return SendResult(success=False, error="Not connected")

        from tools.url_safety import is_safe_url
        if not is_safe_url(image_url):
            logger.warning("[Slack] Blocked unsafe image URL (SSRF protection)")
            return await super().send_image(chat_id, image_url, caption, reply_to, metadata=metadata)

        try:
            import httpx

            # Download the image first
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(image_url)
                response.raise_for_status()

            result = await self._get_client(chat_id).files_upload_v2(
                channel=chat_id,
                content=response.content,
                filename="image.png",
                initial_comment=caption or "",
                thread_ts=self._resolve_thread_ts(reply_to, metadata),
            )

            return SendResult(success=True, raw_response=result)

        except Exception as e:  # pragma: no cover - defensive logging
            logger.warning(
                "[Slack] Failed to upload image from URL %s, falling back to text: %s",
                image_url,
                e,
                exc_info=True,
            )
            # Fall back to sending the URL as text
            text = f"{caption}\n{image_url}" if caption else image_url
            return await self.send(chat_id=chat_id, content=text, reply_to=reply_to)

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Send an audio file to Slack."""
        try:
            return await self._upload_file(chat_id, audio_path, caption, reply_to, metadata)
        except FileNotFoundError:
            return SendResult(success=False, error=f"Audio file not found: {audio_path}")
        except Exception as e:  # pragma: no cover - defensive logging
            logger.error(
                "[Slack] Failed to send audio file %s: %s",
                audio_path,
                e,
                exc_info=True,
            )
            return SendResult(success=False, error=str(e))

    async def send_video(
        self,
        chat_id: str,
        video_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a video file to Slack."""
        if not self._app:
            return SendResult(success=False, error="Not connected")

        if not os.path.exists(video_path):
            return SendResult(success=False, error=f"Video file not found: {video_path}")

        try:
            result = await self._get_client(chat_id).files_upload_v2(
                channel=chat_id,
                file=video_path,
                filename=os.path.basename(video_path),
                initial_comment=caption or "",
                thread_ts=self._resolve_thread_ts(reply_to, metadata),
            )
            return SendResult(success=True, raw_response=result)

        except Exception as e:  # pragma: no cover - defensive logging
            logger.error(
                "[%s] Failed to send video %s: %s",
                self.name,
                video_path,
                e,
                exc_info=True,
            )
            text = f"🎬 Video: {video_path}"
            if caption:
                text = f"{caption}\n{text}"
            return await self.send(chat_id, text, reply_to=reply_to, metadata=metadata)

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a document/file attachment to Slack."""
        if not self._app:
            return SendResult(success=False, error="Not connected")

        if not os.path.exists(file_path):
            return SendResult(success=False, error=f"File not found: {file_path}")

        display_name = file_name or os.path.basename(file_path)

        try:
            result = await self._get_client(chat_id).files_upload_v2(
                channel=chat_id,
                file=file_path,
                filename=display_name,
                initial_comment=caption or "",
                thread_ts=self._resolve_thread_ts(reply_to, metadata),
            )
            return SendResult(success=True, raw_response=result)

        except Exception as e:  # pragma: no cover - defensive logging
            logger.error(
                "[%s] Failed to send document %s: %s",
                self.name,
                file_path,
                e,
                exc_info=True,
            )
            text = f"📎 File: {file_path}"
            if caption:
                text = f"{caption}\n{text}"
            return await self.send(chat_id, text, reply_to=reply_to, metadata=metadata)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        """Get information about a Slack channel."""
        if not self._app:
            return {"name": chat_id, "type": "unknown"}

        try:
            result = await self._get_client(chat_id).conversations_info(channel=chat_id)
            channel = result.get("channel", {})
            is_dm = channel.get("is_im", False)
            return {
                "name": channel.get("name", chat_id),
                "type": "dm" if is_dm else "group",
            }
        except Exception as e:  # pragma: no cover - defensive logging
            logger.error(
                "[Slack] Failed to fetch chat info for %s: %s",
                chat_id,
                e,
                exc_info=True,
            )
            return {"name": chat_id, "type": "unknown"}

    # ----- Internal handlers -----

    def _assistant_thread_key(self, channel_id: str, thread_ts: str) -> Optional[Tuple[str, str]]:
        """Return a stable cache key for Slack assistant thread metadata."""
        if not channel_id or not thread_ts:
            return None
        return (str(channel_id), str(thread_ts))

    def _extract_assistant_thread_metadata(self, event: dict) -> Dict[str, str]:
        """Extract Slack Assistant thread identity data from an event payload."""
        assistant_thread = event.get("assistant_thread") or {}
        context = assistant_thread.get("context") or event.get("context") or {}

        channel_id = (
            assistant_thread.get("channel_id")
            or event.get("channel")
            or context.get("channel_id")
            or ""
        )
        thread_ts = (
            assistant_thread.get("thread_ts")
            or event.get("thread_ts")
            or event.get("message_ts")
            or ""
        )
        user_id = (
            assistant_thread.get("user_id")
            or event.get("user")
            or context.get("user_id")
            or ""
        )
        team_id = (
            event.get("team")
            or event.get("team_id")
            or assistant_thread.get("team_id")
            or ""
        )
        context_channel_id = context.get("channel_id") or ""

        return {
            "channel_id": str(channel_id) if channel_id else "",
            "thread_ts": str(thread_ts) if thread_ts else "",
            "user_id": str(user_id) if user_id else "",
            "team_id": str(team_id) if team_id else "",
            "context_channel_id": str(context_channel_id) if context_channel_id else "",
        }

    def _cache_assistant_thread_metadata(self, metadata: Dict[str, str]) -> None:
        """Remember assistant thread identity data for later message events."""
        channel_id = metadata.get("channel_id", "")
        thread_ts = metadata.get("thread_ts", "")
        key = self._assistant_thread_key(channel_id, thread_ts)
        if not key:
            return

        existing = self._assistant_threads.get(key, {})
        merged = dict(existing)
        merged.update({k: v for k, v in metadata.items() if v})
        self._assistant_threads[key] = merged

        # Evict oldest entries when the cache exceeds the limit
        if len(self._assistant_threads) > self._ASSISTANT_THREADS_MAX:
            excess = len(self._assistant_threads) - self._ASSISTANT_THREADS_MAX // 2
            for old_key in list(self._assistant_threads)[:excess]:
                del self._assistant_threads[old_key]

        team_id = merged.get("team_id", "")
        if team_id and channel_id:
            self._channel_team[channel_id] = team_id

    def _lookup_assistant_thread_metadata(
        self,
        event: dict,
        channel_id: str = "",
        thread_ts: str = "",
    ) -> Dict[str, str]:
        """Load cached assistant-thread metadata that matches the current event."""
        metadata = self._extract_assistant_thread_metadata(event)
        if channel_id and not metadata.get("channel_id"):
            metadata["channel_id"] = channel_id
        if thread_ts and not metadata.get("thread_ts"):
            metadata["thread_ts"] = thread_ts

        key = self._assistant_thread_key(
            metadata.get("channel_id", ""),
            metadata.get("thread_ts", ""),
        )
        cached = self._assistant_threads.get(key, {}) if key else {}
        if cached:
            merged = dict(cached)
            merged.update({k: v for k, v in metadata.items() if v})
            return merged
        return metadata

    def _seed_assistant_thread_session(self, metadata: Dict[str, str]) -> None:
        """Prime the session store so assistant threads get stable user scoping."""
        session_store = getattr(self, "_session_store", None)
        if not session_store:
            return

        channel_id = metadata.get("channel_id", "")
        thread_ts = metadata.get("thread_ts", "")
        user_id = metadata.get("user_id", "")
        if not channel_id or not thread_ts or not user_id:
            return

        source = self.build_source(
            chat_id=channel_id,
            chat_name=channel_id,
            chat_type="dm",
            user_id=user_id,
            thread_id=thread_ts,
            chat_topic=metadata.get("context_channel_id") or None,
        )

        try:
            session_store.get_or_create_session(source)
        except Exception:
            logger.debug(
                "[Slack] Failed to seed assistant thread session for %s/%s",
                channel_id,
                thread_ts,
                exc_info=True,
            )

    async def _handle_assistant_thread_lifecycle_event(self, event: dict) -> None:
        """Handle Slack Assistant lifecycle events that carry user/thread identity."""
        metadata = self._extract_assistant_thread_metadata(event)
        self._cache_assistant_thread_metadata(metadata)
        self._seed_assistant_thread_session(metadata)

    async def _handle_slack_message(self, event: dict) -> None:
        """Handle an incoming Slack message event."""
        # Dedup: Slack Socket Mode can redeliver events after reconnects (#4777)
        event_ts = event.get("ts", "")
        if event_ts:
            now = time.time()
            if event_ts in self._seen_messages:
                return
            self._seen_messages[event_ts] = now
            if len(self._seen_messages) > self._SEEN_MAX:
                cutoff = now - self._SEEN_TTL
                self._seen_messages = {
                    k: v for k, v in self._seen_messages.items()
                    if v > cutoff
                }

        # Mark event received for stale socket detection
        self._mark_event_received()

        # Extract basic info first (needed for channel config resolution)
        channel_id = event.get("channel", "")
        user_id = event.get("user", "")
        ts = event.get("ts", "")
        assistant_meta = self._lookup_assistant_thread_metadata(
            event,
            channel_id=channel_id,
            thread_ts=event.get("thread_ts", ""),
        )
        user_id = event.get("user") or assistant_meta.get("user_id", "")
        if not channel_id:
            channel_id = assistant_meta.get("channel_id", "")
        team_id = (
            event.get("team")
            or event.get("team_id")
            or assistant_meta.get("team_id", "")
        )

        # Track which workspace owns this channel
        if team_id and channel_id:
            self._channel_team[channel_id] = team_id

        # Determine if this is a DM or channel message
        channel_type = event.get("channel_type", "")
        if not channel_type and channel_id.startswith("D"):
            channel_type = "im"
        is_dm = channel_type == "im"

        # Resolve per-channel configuration early (needed for allowBots check)
        channel_name = None  # Will be resolved later if needed
        channel_config = resolve_channel_config(
            channel_id=channel_id,
            channel_name=channel_name,
            global_config=self.config.extra,
        )

        # Ignore bot messages (including our own)
        bot_id = event.get("bot_id")
        is_bot_message = event.get("subtype") == "bot_message"
        
        # Use channel-specific allowBots if set, else global default
        allow_bots = channel_config.allow_bots
        if allow_bots is None:
            allow_bots = self.config.extra.get("allowBots", False)
        
        if bot_id or is_bot_message:
            # Skip our own messages
            if user_id and self._bot_user_id and user_id == self._bot_user_id:
                return
            # Skip other bots unless allowBots is enabled
            if not allow_bots:
                logger.debug("[Slack] Dropping bot message %s (allowBots=%s)", bot_id or "unknown", allow_bots)
                return

        # Handle message subtypes
        subtype = event.get("subtype")
        
        # thread_broadcast: reply posted to thread AND broadcast to channel
        if subtype == "thread_broadcast":
            # Process like a regular message but note it's a broadcast
            logger.debug("[Slack] Received thread_broadcast message")
            # Continue processing below - don't return
        
        # slack_audio: voice message (handle MIME type conversion below)
        if subtype == "slack_audio":
            logger.debug("[Slack] Received voice message (slack_audio subtype)")
            # Continue processing - file handling will convert MIME type
        
        # message_deleted: nothing to process
        if subtype == "message_deleted":
            return

        # message_changed: extract the edited message and re-process it.
        # Slack wraps the new version in event["message"].
        if subtype == "message_changed":
            inner = event.get("message")
            if not inner or inner.get("subtype") == "bot_message":
                return
            # Promote the inner message fields so downstream code sees them
            # at the top level, matching a normal message event.
            event = {**event, **inner, "subtype": None}
            logger.debug("[Slack] Processing edited message %s", inner.get("ts"))

        text = event.get("text", "")

        # Get parent user ID for thread ownership detection
        parent_user_id = event.get("parent_user_id")

        # Build thread_ts for session keying
        if is_dm:
            thread_ts = event.get("thread_ts") or assistant_meta.get("thread_ts")  # None for top-level DMs
        else:
            thread_ts = event.get("thread_ts") or ts  # ts fallback for channels

        # Check for thread participation (cache + persistent session fallback)
        thread_participation_cache = get_thread_participation_cache()
        account_id = "default"  # TODO: Support multi-account
        has_thread_participation = False
        if thread_ts and not is_dm:
            has_thread_participation = await thread_participation_cache.has_participated(
                account_id, channel_id, thread_ts
            )
            # Fallback: check persistent session store (survives restarts)
            if not has_thread_participation:
                has_thread_participation = self._has_active_session_for_thread(
                    channel_id=channel_id,
                    thread_ts=thread_ts,
                    user_id=user_id,
                )

        # Check user authorization (per-channel whitelist)
        if not is_dm and channel_config.users:
            user_allowed, user_reason = is_user_allowed_in_channel(
                user_id=user_id,
                user_name=None,  # Will be resolved later
                channel_config=channel_config,
                global_config=self.config.extra,
            )
            if not user_allowed:
                logger.debug("[Slack] Blocked user %s in channel %s: %s", user_id, channel_id, user_reason)
                return

        # Smart mention detection
        bot_uid = self._team_bot_user_ids.get(team_id, self._bot_user_id)

        # Use channel-specific require_mention if set, else global default
        require_mention = channel_config.require_mention
        if require_mention is None:
            require_mention = self.config.extra.get("require_mention", True)
        mention_result = check_mention_gate(
            text=text,
            bot_user_id=bot_uid,
            is_dm=is_dm,
            thread_ts=thread_ts,
            parent_user_id=parent_user_id,
            has_thread_participation=has_thread_participation,
            require_mention=require_mention,
        )

        if not mention_result.should_respond:
            logger.debug("[Slack] Skipping message: %s", mention_result.reason)
            return

        # Strip the bot mention from text if present
        if mention_result.was_mentioned and bot_uid:
            text = text.replace(f"<@{bot_uid}>", "").strip()

        # Record thread participation on mention so future replies auto-trigger
        if mention_result.was_mentioned and thread_ts and not is_dm:
            await thread_participation_cache.record(account_id, channel_id, thread_ts)

        # Load thread history for context if in a thread and this is a new session
        thread_context_text = ""
        if thread_ts and not is_dm:
            try:
                # Check if this is a new session by looking at the thread participation
                # If we've already participated, the session is continuing
                if not has_thread_participation:
                    # Use channel-specific limit if set, else global default
                    history_limit = channel_config.thread_history_limit
                    if history_limit is None:
                        history_limit = self.config.extra.get("thread_history_limit", 20)
                    
                    thread_context = await load_thread_context(
                        client=self._get_client(channel_id),
                        channel_id=channel_id,
                        thread_ts=thread_ts,
                        current_message_ts=ts,
                        history_limit=history_limit,
                    )
                    if thread_context.thread_history:
                        thread_context_text = format_thread_context_for_prompt(thread_context)
                        logger.debug("[Slack] Loaded %d thread messages for context", len(thread_context.thread_history))
            except Exception as e:
                logger.warning("[Slack] Failed to load thread context: %s", e)

        # Inject thread context into the message if loaded
        if thread_context_text:
            text = f"{thread_context_text}\n\n[Current message]: {text}"

        # Determine message type
        msg_type = MessageType.TEXT
        if text.startswith("/"):
            msg_type = MessageType.COMMAND

        # Handle file attachments
        media_urls = []
        media_types = []
        files = event.get("files", [])
        max_files = self.config.extra.get("maxFiles", 8)
        
        for f in files[:max_files]:  # Limit concurrent file processing
            mimetype = f.get("mimetype", "unknown")
            file_subtype = f.get("subtype", "")
            url = f.get("url_private_download") or f.get("url_private", "")
            
            # Normalize Slack voice message MIME type (slack_audio has video/* but is audio)
            mimetype = normalize_slack_voice_mimetype(mimetype, file_subtype)
            
            if mimetype.startswith("image/") and url:
                try:
                    ext = "." + mimetype.split("/")[-1].split(";")[0]
                    if ext not in (".jpg", ".jpeg", ".png", ".gif", ".webp"):
                        ext = ".jpg"
                    # Slack private URLs require the bot token as auth header
                    cached = await self._download_slack_file(url, ext, team_id=team_id)
                    media_urls.append(cached)
                    media_types.append(mimetype)
                    msg_type = MessageType.PHOTO
                except Exception as e:  # pragma: no cover - defensive logging
                    logger.warning("[Slack] Failed to cache image from %s: %s", url, e, exc_info=True)
            elif mimetype.startswith("audio/") and url:
                try:
                    ext = "." + mimetype.split("/")[-1].split(";")[0]
                    if ext not in (".ogg", ".mp3", ".wav", ".webm", ".m4a"):
                        ext = ".ogg"
                    cached = await self._download_slack_file(url, ext, audio=True, team_id=team_id)
                    media_urls.append(cached)
                    media_types.append(mimetype)
                    msg_type = MessageType.VOICE
                except Exception as e:  # pragma: no cover - defensive logging
                    logger.warning("[Slack] Failed to cache audio from %s: %s", url, e, exc_info=True)
            elif url:
                # Try to handle as a document attachment
                try:
                    original_filename = f.get("name", "")
                    ext = ""
                    if original_filename:
                        _, ext = os.path.splitext(original_filename)
                        ext = ext.lower()

                    # Fallback: reverse-lookup from MIME type
                    if not ext and mimetype:
                        mime_to_ext = {v: k for k, v in SUPPORTED_DOCUMENT_TYPES.items()}
                        ext = mime_to_ext.get(mimetype, "")

                    if ext not in SUPPORTED_DOCUMENT_TYPES:
                        continue  # Skip unsupported file types silently

                    # Check file size (Slack limit: 20 MB for bots)
                    file_size = f.get("size", 0)
                    MAX_DOC_BYTES = 20 * 1024 * 1024
                    if not file_size or file_size > MAX_DOC_BYTES:
                        logger.warning("[Slack] Document too large or unknown size: %s", file_size)
                        continue

                    # Download and cache
                    raw_bytes = await self._download_slack_file_bytes(url, team_id=team_id)
                    cached_path = cache_document_from_bytes(
                        raw_bytes, original_filename or f"document{ext}"
                    )
                    doc_mime = SUPPORTED_DOCUMENT_TYPES[ext]
                    media_urls.append(cached_path)
                    media_types.append(doc_mime)
                    msg_type = MessageType.DOCUMENT
                    logger.debug("[Slack] Cached user document: %s", cached_path)

                    # Inject text content for .txt/.md files (capped at 100 KB)
                    MAX_TEXT_INJECT_BYTES = 100 * 1024
                    if ext in (".md", ".txt") and len(raw_bytes) <= MAX_TEXT_INJECT_BYTES:
                        try:
                            text_content = raw_bytes.decode("utf-8")
                            display_name = original_filename or f"document{ext}"
                            display_name = re.sub(r'[^\w.\- ]', '_', display_name)
                            injection = f"[Content of {display_name}]:\n{text_content}"
                            if text:
                                text = f"{injection}\n\n{text}"
                            else:
                                text = injection
                        except UnicodeDecodeError:
                            pass  # Binary content, skip injection

                except Exception as e:  # pragma: no cover - defensive logging
                    logger.warning("[Slack] Failed to cache document from %s: %s", url, e, exc_info=True)

        # Resolve user display name (cached after first lookup)
        user_name = await self._resolve_user_name(user_id, chat_id=channel_id)

        # Build source
        source = self.build_source(
            chat_id=channel_id,
            chat_name=channel_id,  # Will be resolved later if needed
            chat_type="dm" if is_dm else "group",
            user_id=user_id,
            user_name=user_name,
            thread_id=thread_ts,
        )

        msg_event = MessageEvent(
            text=text,
            message_type=msg_type,
            source=source,
            raw_message=event,
            message_id=ts,
            media_urls=media_urls,
            media_types=media_types,
            reply_to_message_id=thread_ts if thread_ts != ts else None,
        )

        # Add 👀 reaction to acknowledge receipt
        await self._add_reaction(channel_id, ts, "eyes")

        await self.handle_message(msg_event)

        # Record thread participation for future implicit mentions
        if thread_ts and not is_dm:
            await thread_participation_cache.record(account_id, channel_id, thread_ts)

        # Replace 👀 with ✅ when done
        await self._remove_reaction(channel_id, ts, "eyes")
        await self._add_reaction(channel_id, ts, "white_check_mark")

    # ----- Approval button support (Block Kit) -----

    async def send_exec_approval(
        self, chat_id: str, command: str, session_key: str,
        description: str = "dangerous command",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a Block Kit approval prompt with interactive buttons.

        The buttons call ``resolve_gateway_approval()`` to unblock the waiting
        agent thread — same mechanism as the text ``/approve`` flow.
        """
        if not self._app:
            return SendResult(success=False, error="Not connected")

        try:
            cmd_preview = command[:2900] + "..." if len(command) > 2900 else command
            thread_ts = self._resolve_thread_ts(None, metadata)

            blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f":warning: *Command Approval Required*\n"
                            f"```{cmd_preview}```\n"
                            f"Reason: {description}"
                        ),
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Allow Once"},
                            "style": "primary",
                            "action_id": "hermes_approve_once",
                            "value": session_key,
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Allow Session"},
                            "action_id": "hermes_approve_session",
                            "value": session_key,
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Always Allow"},
                            "action_id": "hermes_approve_always",
                            "value": session_key,
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Deny"},
                            "style": "danger",
                            "action_id": "hermes_deny",
                            "value": session_key,
                        },
                    ],
                },
            ]

            kwargs: Dict[str, Any] = {
                "channel": chat_id,
                "text": f"⚠️ Command approval required: {cmd_preview[:100]}",
                "blocks": blocks,
            }
            if thread_ts:
                kwargs["thread_ts"] = thread_ts

            result = await self._get_client(chat_id).chat_postMessage(**kwargs)
            msg_ts = result.get("ts", "")
            if msg_ts:
                self._approval_resolved[msg_ts] = False

            return SendResult(success=True, message_id=msg_ts, raw_response=result)
        except Exception as e:
            logger.error("[Slack] send_exec_approval failed: %s", e, exc_info=True)
            return SendResult(success=False, error=str(e))

    async def _handle_approval_action(self, ack, body, action) -> None:
        """Handle an approval button click from Block Kit."""
        await ack()

        action_id = action.get("action_id", "")
        session_key = action.get("value", "")
        message = body.get("message", {})
        msg_ts = message.get("ts", "")
        channel_id = body.get("channel", {}).get("id", "")
        user_name = body.get("user", {}).get("name", "unknown")

        # Map action_id to approval choice
        choice_map = {
            "hermes_approve_once": "once",
            "hermes_approve_session": "session",
            "hermes_approve_always": "always",
            "hermes_deny": "deny",
        }
        choice = choice_map.get(action_id, "deny")

        # Prevent double-clicks
        if self._approval_resolved.get(msg_ts, False):
            return
        self._approval_resolved[msg_ts] = True

        # Update the message to show the decision and remove buttons
        label_map = {
            "once": f"✅ Approved once by {user_name}",
            "session": f"✅ Approved for session by {user_name}",
            "always": f"✅ Approved permanently by {user_name}",
            "deny": f"❌ Denied by {user_name}",
        }
        decision_text = label_map.get(choice, f"Resolved by {user_name}")

        # Get original text from the section block
        original_text = ""
        for block in message.get("blocks", []):
            if block.get("type") == "section":
                original_text = block.get("text", {}).get("text", "")
                break

        updated_blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": original_text or "Command approval request",
                },
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": decision_text},
                ],
            },
        ]

        try:
            await self._get_client(channel_id).chat_update(
                channel=channel_id,
                ts=msg_ts,
                text=decision_text,
                blocks=updated_blocks,
            )
        except Exception as e:
            logger.warning("[Slack] Failed to update approval message: %s", e)

        # Resolve the approval — this unblocks the agent thread
        try:
            from tools.approval import resolve_gateway_approval
            count = resolve_gateway_approval(session_key, choice)
            logger.info(
                "Slack button resolved %d approval(s) for session %s (choice=%s, user=%s)",
                count, session_key, choice, user_name,
            )
        except Exception as exc:
            logger.error("Failed to resolve gateway approval from Slack button: %s", exc)

        # Clean up stale approval state
        self._approval_resolved.pop(msg_ts, None)

    async def _handle_slash_command(self, command: dict) -> None:
        """Handle /hermes slash command."""
        text = command.get("text", "").strip()
        user_id = command.get("user_id", "")
        channel_id = command.get("channel_id", "")
        team_id = command.get("team_id", "")
        trigger_id = command.get("trigger_id", "")
        response_url = command.get("response_url", "")

        # Track which workspace owns this channel
        if team_id and channel_id:
            self._channel_team[channel_id] = team_id

        # Map subcommands to gateway commands — derived from central registry.
        # Also keep "compact" as a Slack-specific alias for /compress.
        from hermes_cli.commands import slack_subcommand_map
        subcommand_map = slack_subcommand_map()
        subcommand_map["compact"] = "/compress"
        first_word = text.split()[0] if text else ""
        if first_word in subcommand_map:
            # Preserve arguments after the subcommand
            rest = text[len(first_word):].strip()
            text = f"{subcommand_map[first_word]} {rest}".strip() if rest else subcommand_map[first_word]
        elif text:
            pass  # Treat as a regular question
        else:
            text = "/help"

        source = self.build_source(
            chat_id=channel_id,
            chat_type="dm",  # Slash commands are always in DM-like context
            user_id=user_id,
        )

        event = MessageEvent(
            text=text,
            message_type=MessageType.COMMAND if text.startswith("/") else MessageType.TEXT,
            source=source,
            raw_message=command,
        )

        await self.handle_message(event)

    def _has_active_session_for_thread(
        self,
        channel_id: str,
        thread_ts: str,
        user_id: str,
    ) -> bool:
        """Check if there's an active session for a thread.

        Used to determine if thread replies without @mentions should be
        processed (they should if there's an active session).

        Uses ``build_session_key()`` as the single source of truth for key
        construction — avoids the bug where manual key building didn't
        respect ``thread_sessions_per_user`` and ``group_sessions_per_user``
        settings correctly.
        """
        session_store = getattr(self, "_session_store", None)
        if not session_store:
            return False

        try:
            from gateway.session import SessionSource, build_session_key

            source = SessionSource(
                platform=Platform.SLACK,
                chat_id=channel_id,
                chat_type="group",
                user_id=user_id,
                thread_id=thread_ts,
            )

            # Read session isolation settings from the store's config
            store_cfg = getattr(session_store, "config", None)
            gspu = getattr(store_cfg, "group_sessions_per_user", True) if store_cfg else True
            tspu = getattr(store_cfg, "thread_sessions_per_user", False) if store_cfg else False

            session_key = build_session_key(
                source,
                group_sessions_per_user=gspu,
                thread_sessions_per_user=tspu,
            )

            session_store._ensure_loaded()
            return session_key in session_store._entries
        except Exception:
            return False

    async def _handle_block_action(self, body: dict, respond: Any) -> None:
        """Handle interactive Block Kit actions (button clicks, select menus).

        This is called when a user interacts with a Block Kit component that
        has an action_id matching "hermes:.*".

        Args:
            body: The interaction payload from Slack
            respond: Function to respond to the interaction
        """
        import json

        user_id = body.get("user", {}).get("id", "")
        channel_id = body.get("channel", {}).get("id", "")
        message_ts = body.get("message", {}).get("ts", "")

        # Extract action details
        actions = body.get("actions", [])
        if not actions:
            return

        action = actions[0]
        action_id = action.get("action_id", "")
        action_type = action.get("type", "")

        # Parse action_id: hermes:reply_button:N:M or hermes:reply_select:N
        parts = action_id.split(":")
        if len(parts) < 2:
            return

        action_name = parts[1]  # reply_button or reply_select

        # Get the selected value
        value = ""
        if action_type == "button":
            value = action.get("value", "")
        elif action_type == "static_select":
            selected_option = action.get("selected_option", {})
            value = selected_option.get("value", "")

        logger.info(
            "[Slack] Block action: user=%s channel=%s action=%s value=%s",
            user_id, channel_id, action_name, value
        )

        # Build a synthetic message event with the selected value
        text = value

        source = self.build_source(
            chat_id=channel_id,
            chat_type="group",  # Block actions typically in channels
            user_id=user_id,
            thread_id=body.get("message", {}).get("thread_ts"),
        )

        event = MessageEvent(
            text=text,
            message_type=MessageType.TEXT,
            source=source,
            raw_message=body,
        )

        # Process the selection as a message
        await self.handle_message(event)

    async def _download_slack_file(self, url: str, ext: str, audio: bool = False, team_id: str = "") -> str:
        """Download a Slack file using the bot token for auth, with retry.
        
        Includes SSRF protection and HTML detection to prevent credential leaks.
        """
        import asyncio
        import httpx

        # SSRF protection: validate URL points to Slack domain
        try:
            url = validate_slack_file_url(url)
        except ValueError as e:
            logger.warning("[Slack] SSRF protection rejected URL: %s", e)
            raise

        bot_token = self._team_clients[team_id].token if team_id and team_id in self._team_clients else self.config.token
        last_exc = None

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            for attempt in range(3):
                try:
                    response = await client.get(
                        url,
                        headers={"Authorization": f"Bearer {bot_token}"},
                    )
                    response.raise_for_status()

                    # Detect HTML auth/error pages
                    if not audio and looks_like_html_content(response.content):
                        logger.warning("[Slack] Received HTML instead of binary file (auth failure?)")
                        raise ValueError("Received HTML content instead of file")

                    if audio:
                        from gateway.platforms.base import cache_audio_from_bytes
                        return cache_audio_from_bytes(response.content, ext)
                    else:
                        from gateway.platforms.base import cache_image_from_bytes
                        return cache_image_from_bytes(response.content, ext)
                except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
                    last_exc = exc
                    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 429:
                        raise
                    if attempt < 2:
                        logger.debug("Slack file download retry %d/2 for %s: %s",
                                     attempt + 1, url[:80], exc)
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    raise
        raise last_exc

    async def _download_slack_file_bytes(self, url: str, team_id: str = "") -> bytes:
        """Download a Slack file and return raw bytes, with retry.
        
        Includes SSRF protection and HTML detection.
        """
        import asyncio
        import httpx

        # SSRF protection: validate URL points to Slack domain
        try:
            url = validate_slack_file_url(url)
        except ValueError as e:
            logger.warning("[Slack] SSRF protection rejected URL: %s", e)
            raise

        bot_token = self._team_clients[team_id].token if team_id and team_id in self._team_clients else self.config.token
        last_exc = None

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            for attempt in range(3):
                try:
                    response = await client.get(
                        url,
                        headers={"Authorization": f"Bearer {bot_token}"},
                    )
                    response.raise_for_status()

                    # Detect HTML auth/error pages
                    if looks_like_html_content(response.content):
                        logger.warning("[Slack] Received HTML instead of binary file (auth failure?)")
                        raise ValueError("Received HTML content instead of file")

                    return response.content
                except (httpx.TimeoutException, httpx.HTTPStatusError) as exc:
                    last_exc = exc
                    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 429:
                        raise
                    if attempt < 2:
                        logger.debug("Slack file download retry %d/2 for %s: %s",
                                     attempt + 1, url[:80], exc)
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    raise
        raise last_exc

    # -----------------------------------------------------------------------
    # Message Updating
    # -----------------------------------------------------------------------

    async def update_message(
        self,
        message_ref: SlackMessageRef,
        text: str,
        blocks: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """
        Update an existing Slack message.
        
        Useful for:
        - Progress updates on long-running tasks
        - Approval flow (approve/deny/always buttons)
        - Error correction
        
        Args:
            message_ref: Reference to the message to update
            text: New message text
            blocks: Optional new Block Kit blocks
        
        Returns:
            True if update succeeded
        """
        if not self._app:
            logger.error("[Slack] Cannot update message: not connected")
            return False
        
        client = self._get_client(message_ref.channel_id)
        return await update_slack_message(client, message_ref, text, blocks)

    async def send_with_update_ref(
        self,
        chat_id: str,
        content: str,
        ref_id: str,
        blocks: Optional[List[Dict[str, Any]]] = None,
        reply_to: Optional[str] = None,
    ) -> SendResult:
        """
        Send a message and store a reference for later updates.
        
        Args:
            chat_id: Channel ID
            content: Message text
            ref_id: Unique ID to reference this message later
            blocks: Optional Block Kit blocks
            reply_to: Thread parent ID
        
        Returns:
            SendResult with message_id
        """
        result = await self.send(chat_id, content, reply_to=reply_to, blocks=blocks)
        
        if result.success and result.message_id:
            self._pending_messages[ref_id] = SlackMessageRef(
                channel_id=chat_id,
                message_ts=result.message_id,
            )
        
        return result

    async def update_by_ref_id(
        self,
        ref_id: str,
        text: str,
        blocks: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """
        Update a message by its reference ID.
        
        Args:
            ref_id: The reference ID stored when sending
            text: New message text
            blocks: Optional new blocks
        
        Returns:
            True if update succeeded
        """
        ref = self._pending_messages.get(ref_id)
        if not ref:
            logger.warning("[Slack] No message found with ref_id: %s", ref_id)
            return False
        
        return await self.update_message(ref, text, blocks)

    # -----------------------------------------------------------------------
    # Connection Health & Reconnection
    # -----------------------------------------------------------------------

    async def health_check(self) -> SlackProbeResult:
        """
        Check Slack connection health.
        
        Returns:
            SlackProbeResult with connection status
        """
        if not self._app:
            return SlackProbeResult(ok=False, error="not connected")
        
        return await probe_slack_connection(self._app.client)

    def get_connection_state(self) -> SlackConnectionState:
        """Get current connection state."""
        return self._connection_state

    def is_socket_stale(self, threshold_seconds: float = 60.0) -> bool:
        """
        Check if socket appears connected but is stale.
        
        Detects "half-dead" sockets that pass health checks
        but silently stop delivering events.
        
        Args:
            threshold_seconds: Seconds without events to consider stale
        
        Returns:
            True if socket is stale
        """
        return self._connection_state.is_socket_stale(threshold_seconds)

    async def validate_scopes(self) -> SlackScopeValidation:
        """
        Validate OAuth scopes for current connection.
        
        Returns:
            SlackScopeValidation with missing scopes
        """
        if not self._app:
            return SlackScopeValidation(
                valid=False,
                missing_required=list(REQUIRED_SLACK_SCOPES),
                missing_recommended=list(RECOMMENDED_SLACK_SCOPES),
                all_scopes=[],
            )
        
        scopes = await fetch_slack_scopes(self._app.client)
        validation = validate_slack_scopes(scopes)
        
        if not validation.valid:
            logger.warning(validation.format_warning())
        
        return validation

    def _mark_event_received(self) -> None:
        """Mark that an event was received (called by message handler)."""
        self._connection_state.mark_event_received()

