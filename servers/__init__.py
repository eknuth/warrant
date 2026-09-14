"""MCP servers for the systems an agent acts on.

Each is its own module: gitea_mcp (W3), postgres_mcp (W8), and mail_mcp (W9).
They exist so an agent's action lands somewhere with a record, rather than in a
mock that cannot be checked afterwards.
"""
