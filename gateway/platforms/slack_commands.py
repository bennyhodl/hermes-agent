"""
Slack slash command handlers.

Provides interactive slash commands for:
- /hermes skills - List available skills
- /hermes status - Show connection status
- /hermes config - Manage configuration
- /hermes help - Show available commands
"""

import logging
from typing import Dict, List, Any, Optional, Callable, Awaitable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SlashCommandContext:
    """Context for slash command execution."""
    user_id: str
    channel_id: str
    team_id: str
    trigger_id: str
    response_url: str
    adapter: Any  # SlackAdapter


@dataclass
class SlashCommandResult:
    """Result of slash command execution."""
    text: str
    blocks: Optional[List[Dict]] = None
    response_type: str = "ephemeral"  # "ephemeral" or "in_channel"


def build_header_block(text: str) -> Dict:
    """Build a header block."""
    return {
        "type": "header",
        "text": {"type": "plain_text", "text": text[:150]},
    }


def build_section_block(text: str) -> Dict:
    """Build a section block with markdown text."""
    return {
        "type": "section",
        "text": {"type": "mrkdwn", "text": text[:3000]},
    }


def build_context_block(elements: List[str]) -> Dict:
    """Build a context block."""
    return {
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": elem[:300]}
            for elem in elements
        ],
    }


def build_divider_block() -> Dict:
    """Build a divider block."""
    return {"type": "divider"}


def build_actions_block(elements: List[Dict]) -> Dict:
    """Build an actions block."""
    return {
        "type": "actions",
        "elements": elements[:25],
    }


def build_button(
    text: str,
    action_id: str,
    value: str = "",
    style: Optional[str] = None,
) -> Dict:
    """Build a button element."""
    button = {
        "type": "button",
        "text": {"type": "plain_text", "text": text[:75]},
        "action_id": action_id,
        "value": value,
    }
    if style in ("primary", "danger"):
        button["style"] = style
    return button


def build_select_menu(
    placeholder: str,
    action_id: str,
    options: List[Dict[str, str]],
) -> Dict:
    """Build a static select menu."""
    return {
        "type": "static_select",
        "placeholder": {"type": "plain_text", "text": placeholder[:150]},
        "action_id": action_id,
        "options": [
            {
                "text": {"type": "plain_text", "text": opt["text"][:75]},
                "value": opt["value"][:75],
            }
            for opt in options[:100]
        ],
    }


# ---------------------------------------------------------------------------
# Command Handlers
# ---------------------------------------------------------------------------

async def handle_help_command(ctx: SlashCommandContext) -> SlashCommandResult:
    """Handle /hermes help command."""
    blocks = [
        build_header_block("Hermes Agent Help"),
        build_section_block(
            "*Available Commands:*\n\n"
            "• `/hermes help` - Show this help message\n"
            "• `/hermes skills` - List available skills\n"
            "• `/hermes status` - Show connection status\n"
            "• `/hermes config` - View configuration\n"
            "• `/hermes compact` - Compact conversation\n"
            "• `/hermes clear` - Clear conversation\n\n"
            "You can also just ask questions directly!"
        ),
        build_divider_block(),
        build_context_block([
            "Hermes Agent v1.0 • Slack Integration",
        ]),
    ]
    
    return SlashCommandResult(
        text="Hermes Help",
        blocks=blocks,
    )


async def handle_skills_command(ctx: SlashCommandContext) -> SlashCommandResult:
    """Handle /hermes skills command."""
    try:
        # Import skills list from tools
        from tools.skills_tool import skills_list
        import json as json_module
        
        result_json = skills_list()
        result = json_module.loads(result_json)
        
        if not result.get("success"):
            return SlashCommandResult(
                text=f"Error loading skills: {result.get('error', 'unknown error')}",
            )
        
        skills = result.get("skills", [])
        categories = result.get("categories", [])
        
        if not skills:
            message = result.get("message", "No skills found.")
            return SlashCommandResult(
                text=message,
            )
        
        # Group skills by category
        skill_by_category: Dict[str, List[Dict]] = {}
        for skill in skills[:50]:  # Limit to 50 skills
            cat = skill.get("category", "general")
            if cat not in skill_by_category:
                skill_by_category[cat] = []
            skill_by_category[cat].append(skill)
        
        blocks = [build_header_block(f"Available Skills ({len(skills)} total)")]
        
        for category in list(skill_by_category.keys())[:10]:  # Max 10 categories
            skill_list = skill_by_category[category]
            lines = []
            for s in skill_list[:10]:  # Max 10 skills per category
                name = s.get("name", "unknown")
                desc = s.get("description", "")[:60]
                if desc:
                    lines.append(f"• `{name}` - {desc}")
                else:
                    lines.append(f"• `{name}`")
            
            text = f"*{category.title()}*\n" + "\n".join(lines)
            blocks.append(build_section_block(text))
        
        if len(skills) > 50:
            blocks.append(build_context_block([
                f"Showing 50 of {len(skills)} skills. Use `hermes skills list` in CLI for full list.",
            ]))
        
        return SlashCommandResult(
            text=f"Available Skills ({len(skills)} total)",
            blocks=blocks,
        )
    
    except Exception as e:
        logger.error("[Slack] Skills command error: %s", e, exc_info=True)
        return SlashCommandResult(
            text=f"Error loading skills. Use `hermes skills list` in CLI.",
        )


async def handle_status_command(ctx: SlashCommandContext) -> SlashCommandResult:
    """Handle /hermes status command."""
    adapter = ctx.adapter
    
    # Get connection state
    state = adapter.get_connection_state()
    
    status_emoji = {
        "connected": ":large_green_circle:",
        "disconnected": ":red_circle:",
        "connecting": ":large_yellow_circle:",
        "reconnecting": ":large_yellow_circle:",
        "error": ":red_circle:",
    }.get(state.status.value, ":white_circle:")
    
    # Get health check
    try:
        probe = await adapter.health_check()
        health_status = f"Latency: {probe.elapsed_ms:.0f}ms" if probe.ok else f"Error: {probe.error}"
    except Exception as e:
        health_status = f"Health check failed: {e}"
    
    blocks = [
        build_header_block("Hermes Status"),
        build_section_block(
            f"*Connection:* {status_emoji} {state.status.value.title()}\n"
            f"*Health:* {health_status}\n"
            f"*Reconnect Attempts:* {state.reconnect_attempts}"
        ),
    ]
    
    # Add last event time if available
    if state.last_event_at:
        import time
        seconds_ago = time.time() - state.last_event_at
        blocks.append(build_context_block([
            f"Last event: {seconds_ago:.0f}s ago",
        ]))
    
    # Add stale socket warning
    if adapter.is_socket_stale():
        blocks.append(build_section_block(
            ":warning: *Warning:* Socket appears stale (no recent events)"
        ))
    
    return SlashCommandResult(
        text=f"Status: {state.status.value}",
        blocks=blocks,
    )


async def handle_config_command(ctx: SlashCommandContext) -> SlashCommandResult:
    """Handle /hermes config command."""
    adapter = ctx.adapter
    config = adapter.config
    
    # Build config summary (don't expose sensitive values)
    blocks = [
        build_header_block("Hermes Configuration"),
        build_section_block(
            f"*Platform:* Slack\n"
            f"*Token Set:* {'Yes' if config.token else 'No'}\n"
            f"*Allowed Users:* {len(config.extra.get('allowed_users', []))} users"
        ),
    ]
    
    # Show extra config options
    extra = config.extra or {}
    if extra:
        extra_items = []
        for key, value in list(extra.items())[:10]:
            if key in ("token", "bot_token", "app_token", "signing_secret"):
                continue
            if isinstance(value, str) and len(value) > 50:
                value = value[:50] + "..."
            extra_items.append(f"• `{key}`: {value}")
        
        if extra_items:
            blocks.append(build_section_block(
                "*Extra Config:*\n" + "\n".join(extra_items)
            ))
    
    return SlashCommandResult(
        text="Configuration",
        blocks=blocks,
    )


# ---------------------------------------------------------------------------
# Command Registry
# ---------------------------------------------------------------------------

SLASH_COMMANDS: Dict[str, Callable[[SlashCommandContext], Awaitable[SlashCommandResult]]] = {
    "help": handle_help_command,
    "skills": handle_skills_command,
    "status": handle_status_command,
    "config": handle_config_command,
}


async def dispatch_slash_command(
    text: str,
    ctx: SlashCommandContext,
) -> SlashCommandResult:
    """
    Dispatch a slash command to the appropriate handler.
    
    Args:
        text: Command text (after /hermes)
        ctx: Slash command context
    
    Returns:
        SlashCommandResult with response
    """
    parts = text.strip().split(None, 1)
    command = parts[0].lower() if parts else "help"
    args = parts[1] if len(parts) > 1 else ""
    
    handler = SLASH_COMMANDS.get(command)
    
    if handler:
        try:
            return await handler(ctx)
        except Exception as e:
            logger.error("[Slack] Slash command error: %s", e, exc_info=True)
            return SlashCommandResult(
                text=f"Error executing command: {e}",
            )
    
    # Unknown command - return help
    return SlashCommandResult(
        text=f"Unknown command: `{command}`. Use `/hermes help` for available commands.",
    )
